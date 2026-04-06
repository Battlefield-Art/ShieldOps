"""Admin-only tenant management routes (issue #216).

GET /api/v1/admin/tenants  → list all tenants with billing status
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends

from shieldops.api.auth.dependencies import require_role
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes.tenant_signup import get_store

logger = structlog.get_logger()

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/tenants")
async def list_tenants(
    _admin: UserResponse = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Return every organization with its billing status. Admin only."""
    store = get_store()
    tenants: list[dict[str, Any]] = []
    for org in store.list_orgs():
        tenants.append(
            {
                "org_id": org.id,
                "name": org.name,
                "owner_email": org.owner_email,
                "plan": org.plan,
                "status": org.status,
                "stripe_customer_id": org.stripe_customer_id,
                "stripe_subscription_id": org.stripe_subscription_id,
                "created_at": org.created_at.isoformat(),
                "trial_ends_at": (org.trial_ends_at.isoformat() if org.trial_ends_at else None),
            }
        )
    return {"count": len(tenants), "tenants": tenants}
