"""Tenant billing enforcement middleware (issue #216).

Blocks API calls when an organization's Stripe subscription is
``canceled`` or ``past_due`` beyond the grace period.  A 14-day grace
window is honored for ``past_due`` subscriptions so short payment
failures don't immediately break production traffic.

Organizations in ``trialing``, ``active`` or ``incomplete`` states pass
through unchanged.  Requests without org context, health/billing/docs
paths, and signup endpoints are exempt.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from shieldops.api.routes.tenant_signup import get_store

logger = structlog.get_logger()

GRACE_PERIOD_DAYS = 14

_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/health",
    "/ready",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/api/v1/docs",
    "/api/v1/openapi.json",
    "/api/v1/billing",
    "/api/v1/webhooks",
    "/api/v1/auth",
    "/api/v1/signup",
)

BLOCKED_STATUSES = {"canceled"}
GRACE_STATUSES = {"past_due"}


def _is_exempt(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _EXEMPT_PREFIXES)


def _past_grace(org_updated_at: datetime | None) -> bool:
    """Return True if the subscription has been past_due beyond the grace window."""
    if org_updated_at is None:
        return False
    if org_updated_at.tzinfo is None:
        org_updated_at = org_updated_at.replace(tzinfo=UTC)
    return datetime.now(UTC) - org_updated_at > timedelta(days=GRACE_PERIOD_DAYS)


def _build_402(message: str, status_value: str) -> JSONResponse:
    return JSONResponse(
        status_code=402,
        content={
            "detail": message,
            "subscription_status": status_value,
            "upgrade_url": "/api/v1/billing/portal",
        },
        headers={"X-Subscription-Status": status_value},
    )


class TenantBillingEnforcementMiddleware(BaseHTTPMiddleware):
    """Reject API traffic for canceled / long-past-due subscriptions."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        path = request.url.path
        if _is_exempt(path):
            return await call_next(request)

        org_id: str | None = getattr(request.state, "organization_id", None)
        if org_id is None:
            return await call_next(request)

        store = get_store()
        org = store.get_org(org_id)
        if org is None:
            return await call_next(request)

        status_value = org.status

        if status_value in BLOCKED_STATUSES:
            logger.warning(
                "tenant_billing_blocked",
                org_id=org_id,
                status=status_value,
            )
            return _build_402(
                message="Subscription canceled. Re-subscribe to continue.",
                status_value=status_value,
            )

        if status_value in GRACE_STATUSES and _past_grace(
            getattr(org, "updated_at", None) or org.created_at
        ):
            logger.warning(
                "tenant_billing_past_grace",
                org_id=org_id,
                status=status_value,
            )
            return _build_402(
                message=(
                    f"Payment past due beyond {GRACE_PERIOD_DAYS}-day grace period. "
                    "Update billing to continue."
                ),
                status_value=status_value,
            )

        response = await call_next(request)
        response.headers["X-Subscription-Status"] = status_value
        return response
