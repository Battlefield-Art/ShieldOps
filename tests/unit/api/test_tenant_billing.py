"""Tests for tenant Stripe billing flow (issue #216)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from shieldops.api.middleware.tenant_billing_enforcement import (
    TenantBillingEnforcementMiddleware,
)
from shieldops.api.routes import tenant_billing, tenant_signup

# ---------------------------------------------------------------------------
# Fake Stripe SDK
# ---------------------------------------------------------------------------


class _FakeStripe:
    """Minimal duck-typed Stripe module suitable for unit tests."""

    def __init__(self) -> None:
        self.customers: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []
        self.portal_sessions: list[dict[str, Any]] = []

        fake = self

        class Customer:
            @staticmethod
            def create(**kwargs: Any) -> dict[str, Any]:
                cust = {"id": f"cus_test_{len(fake.customers) + 1}", **kwargs}
                fake.customers.append(cust)
                return cust

        class _CheckoutSession:
            @staticmethod
            def create(**kwargs: Any) -> dict[str, Any]:
                sess = {
                    "id": f"cs_test_{len(fake.sessions) + 1}",
                    "url": f"https://checkout.stripe.test/{len(fake.sessions) + 1}",
                    **kwargs,
                }
                fake.sessions.append(sess)
                return sess

        class _Checkout:
            Session = _CheckoutSession

        class _PortalSession:
            @staticmethod
            def create(**kwargs: Any) -> dict[str, Any]:
                sess = {
                    "id": f"bps_test_{len(fake.portal_sessions) + 1}",
                    "url": f"https://billing.stripe.test/{len(fake.portal_sessions) + 1}",
                    **kwargs,
                }
                fake.portal_sessions.append(sess)
                return sess

        class _BillingPortal:
            Session = _PortalSession

        class Webhook:
            @staticmethod
            def construct_event(payload: bytes, sig_header: str, secret: str) -> dict[str, Any]:
                return json.loads(payload.decode())

        self.Customer = Customer
        self.checkout = _Checkout
        self.billing_portal = _BillingPortal
        self.Webhook = Webhook


@pytest.fixture(autouse=True)
def _reset_state() -> None:
    tenant_signup.reset_store()
    tenant_billing.set_stripe_module(_FakeStripe())
    yield
    tenant_signup.reset_store()
    tenant_billing.set_stripe_module(None)


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(tenant_signup.router, prefix="/api/v1")
    app.include_router(tenant_billing.router, prefix="/api/v1")
    return TestClient(app)


def _signup(client: TestClient) -> dict[str, Any]:
    return client.post(
        "/api/v1/signup",
        json={
            "email": "founder@example.com",
            "org_name": "Acme",
            "password": "correct-horse-battery",
        },
    ).json()


# ---------------------------------------------------------------------------
# Plans + checkout
# ---------------------------------------------------------------------------


class TestPlans:
    def test_list_plans(self, client: TestClient) -> None:
        resp = client.get("/api/v1/billing/plans")
        assert resp.status_code == 200
        keys = {p["key"] for p in resp.json()["plans"]}
        assert keys == {"starter", "professional", "enterprise"}


class TestCheckout:
    def test_checkout_returns_url(self, client: TestClient) -> None:
        signup = _signup(client)
        resp = client.post(
            "/api/v1/billing/checkout",
            json={"org_id": signup["org_id"], "plan": "starter"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["checkout_url"].startswith("https://checkout.stripe.test/")
        assert body["session_id"].startswith("cs_test_")

        org = tenant_signup.get_store().get_org(signup["org_id"])
        assert org is not None and org.stripe_customer_id is not None

    def test_checkout_unknown_plan(self, client: TestClient) -> None:
        signup = _signup(client)
        resp = client.post(
            "/api/v1/billing/checkout",
            json={"org_id": signup["org_id"], "plan": "diamond"},
        )
        assert resp.status_code == 400

    def test_checkout_unknown_org(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/billing/checkout",
            json={"org_id": "org-missing", "plan": "starter"},
        )
        assert resp.status_code == 404


class TestPortal:
    def test_portal_requires_customer(self, client: TestClient) -> None:
        signup = _signup(client)
        resp = client.get(
            "/api/v1/billing/portal",
            params={"org_id": signup["org_id"]},
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_portal_redirects(self, client: TestClient) -> None:
        signup = _signup(client)
        client.post(
            "/api/v1/billing/checkout",
            json={"org_id": signup["org_id"], "plan": "starter"},
        )
        resp = client.get(
            "/api/v1/billing/portal",
            params={"org_id": signup["org_id"]},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("https://billing.stripe.test/")


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


class TestWebhook:
    def _checkout_org(self, client: TestClient) -> tuple[str, str]:
        signup = _signup(client)
        client.post(
            "/api/v1/billing/checkout",
            json={"org_id": signup["org_id"], "plan": "starter"},
        )
        org = tenant_signup.get_store().get_org(signup["org_id"])
        assert org is not None and org.stripe_customer_id is not None
        return signup["org_id"], org.stripe_customer_id

    def test_invoice_paid_activates(self, client: TestClient) -> None:
        org_id, customer_id = self._checkout_org(client)
        resp = client.post(
            "/api/v1/billing/webhook",
            content=json.dumps(
                {
                    "type": "invoice.paid",
                    "data": {"object": {"customer": customer_id}},
                }
            ),
        )
        assert resp.status_code == 200
        assert resp.json() == {
            "received": True,
            "event_type": "invoice.paid",
            "handled": True,
        }
        org = tenant_signup.get_store().get_org(org_id)
        assert org is not None and org.status == "active"

    def test_subscription_updated_sets_status(self, client: TestClient) -> None:
        org_id, customer_id = self._checkout_org(client)
        client.post(
            "/api/v1/billing/webhook",
            content=json.dumps(
                {
                    "type": "customer.subscription.updated",
                    "data": {
                        "object": {
                            "id": "sub_test_1",
                            "customer": customer_id,
                            "status": "past_due",
                        }
                    },
                }
            ),
        )
        org = tenant_signup.get_store().get_org(org_id)
        assert org is not None
        assert org.status == "past_due"
        assert org.stripe_subscription_id == "sub_test_1"

    def test_subscription_deleted_cancels(self, client: TestClient) -> None:
        org_id, customer_id = self._checkout_org(client)
        client.post(
            "/api/v1/billing/webhook",
            content=json.dumps(
                {
                    "type": "customer.subscription.deleted",
                    "data": {"object": {"customer": customer_id}},
                }
            ),
        )
        org = tenant_signup.get_store().get_org(org_id)
        assert org is not None and org.status == "canceled"

    def test_unknown_event_not_handled(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/billing/webhook",
            content=json.dumps({"type": "ping", "data": {"object": {}}}),
        )
        assert resp.status_code == 200
        assert resp.json()["handled"] is False


# ---------------------------------------------------------------------------
# Enforcement middleware
# ---------------------------------------------------------------------------


class TestBillingEnforcement:
    def _build_app(self) -> FastAPI:
        app = FastAPI()
        app.include_router(tenant_signup.router, prefix="/api/v1")
        app.include_router(tenant_billing.router, prefix="/api/v1")

        app.add_middleware(TenantBillingEnforcementMiddleware)

        @app.middleware("http")
        async def _inject_org(request: Request, call_next):  # type: ignore[no-untyped-def]
            org_id = request.headers.get("X-Org-Id")
            if org_id:
                request.state.organization_id = org_id
            return await call_next(request)

        @app.get("/api/v1/protected")
        async def _protected() -> dict[str, str]:
            return {"ok": "yes"}

        return app

    def test_active_passes_through(self) -> None:
        app = self._build_app()
        client = TestClient(app)
        signup = _signup(client)
        org_id = signup["org_id"]
        tenant_signup.get_store().update_org(org_id, status="active")

        resp = client.get("/api/v1/protected", headers={"X-Org-Id": org_id})
        assert resp.status_code == 200
        assert resp.headers["X-Subscription-Status"] == "active"

    def test_canceled_blocked(self) -> None:
        app = self._build_app()
        client = TestClient(app)
        signup = _signup(client)
        org_id = signup["org_id"]
        tenant_signup.get_store().update_org(org_id, status="canceled")

        resp = client.get("/api/v1/protected", headers={"X-Org-Id": org_id})
        assert resp.status_code == 402
        assert resp.json()["subscription_status"] == "canceled"

    def test_past_due_within_grace_passes(self) -> None:
        app = self._build_app()
        client = TestClient(app)
        signup = _signup(client)
        org_id = signup["org_id"]
        org = tenant_signup.get_store().update_org(
            org_id,
            status="past_due",
            created_at=datetime.now(UTC) - timedelta(days=3),
        )
        assert org is not None

        resp = client.get("/api/v1/protected", headers={"X-Org-Id": org_id})
        assert resp.status_code == 200

    def test_past_due_beyond_grace_blocked(self) -> None:
        app = self._build_app()
        client = TestClient(app)
        signup = _signup(client)
        org_id = signup["org_id"]
        tenant_signup.get_store().update_org(
            org_id,
            status="past_due",
            created_at=datetime.now(UTC) - timedelta(days=30),
        )

        resp = client.get("/api/v1/protected", headers={"X-Org-Id": org_id})
        assert resp.status_code == 402
        assert resp.json()["subscription_status"] == "past_due"

    def test_signup_path_exempt_even_when_canceled(self) -> None:
        app = self._build_app()
        client = TestClient(app)
        # No org present yet; signup must go through the middleware cleanly.
        resp = client.post(
            "/api/v1/signup",
            json={
                "email": "new@example.com",
                "org_name": "Acme",
                "password": "correct-horse-battery",
            },
        )
        assert resp.status_code == 201
