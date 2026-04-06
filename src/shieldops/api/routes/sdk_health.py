"""SDK health check endpoint (#213).

Used by the SDK to verify API key validity and connectivity before use.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/sdk", tags=["SDK"])


class SDKHealthResponse(BaseModel):
    status: str = "healthy"
    api_version: str = "v1"
    org_id: str
    rate_limit_remaining: int = 10000
    message: str = "ShieldOps SDK can reach the API and the key is valid."


@router.get("/health", response_model=SDKHealthResponse)
async def sdk_health(user: UserResponse = Depends(get_current_user)) -> SDKHealthResponse:
    """Validate API key and return connectivity info.

    Called by the SDK at startup to confirm the key is valid and the
    endpoint is reachable before the first `check()` call.
    """
    org_id = (
        getattr(user, "org_id", None)
        or getattr(user, "tenant_id", None)
        or getattr(user, "id", "default")
    )
    logger.debug("sdk.health_check", org_id=org_id)
    return SDKHealthResponse(org_id=org_id)
