"""Tenant-scoped Stripe billing routes (issue #216).

This module is intentionally independent from the pre-existing
``routes/billing.py`` module (which covers plan catalog + usage).  It
focuses on the self-service tenant signup billing flow:

    POST /api/v1/billing/checkout   → Stripe Checkout session
    POST /api/v1/billing/webhook    → Stripe webhook handler
    GET  /api/v1/billing/portal     → Stripe Customer Portal redirect

Stripe is imported lazily so the module (and its tests) can run without
the ``stripe`` package installed.  Tests inject a fake Stripe client via
:func:`set_stripe_module`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from shieldops.api.routes.tenant_signup import get_store

logger = structlog.get_logger()

router = APIRouter(prefix="/billing", tags=["Billing"])


# ---------------------------------------------------------------------------
# Plan catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    key: str
    name: str
    price_cents: int  # monthly
    agent_limit: int | None  # None = unlimited
    stripe_price_env: str  # env var holding the Stripe Price ID


PLANS: dict[str, Plan] = {
    "starter": Plan(
        key="starter",
        name="Starter",
        price_cents=200_000,
        agent_limit=10,
        stripe_price_env="STRIPE_PRICE_STARTER",
    ),
    "professional": Plan(
        key="professional",
        name="Professional",
        price_cents=800_000,
        agent_limit=50,
        stripe_price_env="STRIPE_PRICE_PROFESSIONAL",
    ),
    "enterprise": Plan(
        key="enterprise",
        name="Enterprise",
        price_cents=2_500_000,
        agent_limit=None,
        stripe_price_env="STRIPE_PRICE_ENTERPRISE",
    ),
}


# ---------------------------------------------------------------------------
# Stripe client (lazy import + test-injectable)
# ---------------------------------------------------------------------------


_stripe_module: Any | None = None


def set_stripe_module(module: Any | None) -> None:
    """Inject a (fake) stripe module — used by tests."""
    global _stripe_module
    _stripe_module = module


def _get_stripe() -> Any:
    """Return an initialised stripe client.

    Performs a lazy import so environments without the package still work.
    """
    global _stripe_module
    if _stripe_module is not None:
        return _stripe_module
    try:
        import stripe  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised only when missing
        raise HTTPException(
            status_code=503,
            detail="Stripe SDK not installed",
        ) from exc
    api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="STRIPE_SECRET_KEY not configured")
    stripe.api_key = api_key
    _stripe_module = stripe
    return stripe


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CheckoutRequest(BaseModel):
    org_id: str = Field(min_length=1)
    plan: str = Field(min_length=1)
    success_url: str = "https://app.shieldops.ai/billing/success"
    cancel_url: str = "https://app.shieldops.ai/billing/cancel"
    model_config = {"extra": "forbid"}


class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: str


class WebhookResponse(BaseModel):
    received: bool
    event_type: str
    handled: bool


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/plans")
async def list_plans() -> dict[str, Any]:
    """Return the static plan catalog."""
    return {
        "plans": [
            {
                "key": p.key,
                "name": p.name,
                "price_cents": p.price_cents,
                "price_display": f"${p.price_cents // 100:,}/mo",
                "agent_limit": p.agent_limit,
            }
            for p in PLANS.values()
        ]
    }


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(payload: CheckoutRequest) -> CheckoutResponse:
    """Create a Stripe Checkout session for plan selection."""
    if payload.plan not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {payload.plan}")

    store = get_store()
    org = store.get_org(payload.org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    plan = PLANS[payload.plan]
    price_id = os.environ.get(plan.stripe_price_env, f"price_mock_{plan.key}")
    stripe = _get_stripe()

    # Ensure a Stripe customer exists
    customer_id = org.stripe_customer_id
    if customer_id is None:
        customer = stripe.Customer.create(
            email=org.owner_email,
            name=org.name,
            metadata={"org_id": org.id},
        )
        customer_id = customer["id"] if isinstance(customer, dict) else customer.id
        store.update_org(org.id, stripe_customer_id=customer_id)

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=payload.success_url,
        cancel_url=payload.cancel_url,
        metadata={"org_id": org.id, "plan": plan.key},
    )
    session_url = session["url"] if isinstance(session, dict) else session.url
    session_id = session["id"] if isinstance(session, dict) else session.id

    logger.info(
        "tenant_billing_checkout_created",
        org_id=org.id,
        plan=plan.key,
        session_id=session_id,
    )
    return CheckoutResponse(checkout_url=session_url, session_id=session_id)


@router.get("/portal")
async def billing_portal(org_id: str) -> RedirectResponse:
    """Redirect to the Stripe Customer Portal for self-service upgrades."""
    store = get_store()
    org = store.get_org(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.stripe_customer_id is None:
        raise HTTPException(
            status_code=400,
            detail="Organization has no Stripe customer. Complete checkout first.",
        )

    stripe = _get_stripe()
    session = stripe.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url="https://app.shieldops.ai/settings/billing",
    )
    url = session["url"] if isinstance(session, dict) else session.url
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


def _extract_event(payload: bytes, sig_header: str | None) -> dict[str, Any]:
    """Verify + parse a Stripe webhook event."""
    stripe = _get_stripe()
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if webhook_secret and sig_header:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        except Exception as exc:  # pragma: no cover - signature specifics vary
            raise HTTPException(status_code=400, detail=f"Invalid signature: {exc}") from exc
        return event if isinstance(event, dict) else event.to_dict()

    # Unsigned fallback (dev/test)
    import json

    try:
        return dict(json.loads(payload.decode() or "{}"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc


def _handle_event(event: dict[str, Any]) -> bool:
    """Apply a Stripe webhook event to the tenant store."""
    event_type = str(event.get("type", ""))
    data_object = event.get("data", {}).get("object", {}) if isinstance(event, dict) else {}
    store = get_store()

    if event_type == "invoice.paid":
        customer_id = data_object.get("customer")
        for org in store.list_orgs():
            if org.stripe_customer_id == customer_id:
                store.update_org(org.id, status="active")
                return True
        return False

    if event_type == "customer.subscription.updated":
        customer_id = data_object.get("customer")
        sub_id = data_object.get("id")
        new_status = data_object.get("status", "active")
        for org in store.list_orgs():
            if org.stripe_customer_id == customer_id:
                store.update_org(
                    org.id,
                    stripe_subscription_id=sub_id,
                    status=new_status,
                )
                return True
        return False

    if event_type == "customer.subscription.deleted":
        customer_id = data_object.get("customer")
        for org in store.list_orgs():
            if org.stripe_customer_id == customer_id:
                store.update_org(org.id, status="canceled")
                return True
        return False

    return False


@router.post("/webhook", response_model=WebhookResponse)
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
) -> WebhookResponse:
    """Handle Stripe webhook events for subscription lifecycle."""
    payload = await request.body()
    event = _extract_event(payload, stripe_signature)
    event_type = str(event.get("type", "unknown"))

    handled = _handle_event(event)
    logger.info(
        "tenant_billing_webhook",
        event_type=event_type,
        handled=handled,
    )
    return WebhookResponse(received=True, event_type=event_type, handled=handled)
