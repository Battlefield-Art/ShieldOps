"""License management API routes.

Endpoints:

- POST /licenses            — issue a new signed license (admin only)
- GET  /licenses/current    — get current org's license + live agent usage
- POST /licenses/validate   — validate an arbitrary license JWT
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.licensing import (
    License,
    LicenseError,
    LicenseStatus,
    LicenseTier,
    LicenseValidator,
)
from shieldops.licensing.signer import sign_license

logger = structlog.get_logger()

router = APIRouter(prefix="/licenses", tags=["Licensing"])

# Module-level validator + current license; wired via setters at startup
_validator: LicenseValidator | None = None
_current_license: License | None = None
_current_jwt: str | None = None
_signing_key: str | None = None
_signing_algorithm: str = "RS256"
_agent_count_provider: Any = None  # Callable[[], int]


# --------------------------------------------------------------------- #
# Wiring helpers (called from app.py startup)
# --------------------------------------------------------------------- #
def set_validator(validator: LicenseValidator) -> None:
    global _validator
    _validator = validator


def set_current_license(license: License | None, jwt_token: str | None = None) -> None:
    global _current_license, _current_jwt
    _current_license = license
    _current_jwt = jwt_token


def set_signing_key(key: str, algorithm: str = "RS256") -> None:
    global _signing_key, _signing_algorithm
    _signing_key = key
    _signing_algorithm = algorithm


def set_agent_count_provider(provider: Any) -> None:
    """Register a callable returning the live agent count (int)."""
    global _agent_count_provider
    _agent_count_provider = provider


def _require_admin(user: UserResponse) -> None:
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required for license management",
        )


def _get_agent_count() -> int:
    if _agent_count_provider is None:
        return 0
    try:
        value = _agent_count_provider()
        return int(value)
    except Exception as exc:  # noqa: BLE001
        logger.warning("license_agent_count_provider_failed", error=str(exc))
        return 0


# --------------------------------------------------------------------- #
# Request/response models
# --------------------------------------------------------------------- #
class IssueLicenseRequest(BaseModel):
    org_id: str
    tier: LicenseTier
    expires_at: datetime
    agent_limit: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    model_config = {"extra": "forbid"}


class IssueLicenseResponse(BaseModel):
    jwt: str
    license: License


class ValidateLicenseRequest(BaseModel):
    jwt: str
    model_config = {"extra": "forbid"}


class LicenseStatusResponse(BaseModel):
    license: License | None
    status: LicenseStatus
    agents_used: int
    agents_limit: int
    days_until_expiry: int | None


# --------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------- #
@router.post("", response_model=IssueLicenseResponse, status_code=status.HTTP_201_CREATED)
async def issue_license(
    req: IssueLicenseRequest,
    user: UserResponse = Depends(get_current_user),
) -> IssueLicenseResponse:
    """Issue a new signed license (admin only)."""
    _require_admin(user)

    key = _signing_key or os.getenv("LICENSE_SIGNING_KEY")
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="license signing key not configured",
        )

    limit = req.agent_limit
    if limit is None:
        limit = LicenseTier.agent_limit(req.tier)

    try:
        if _signing_algorithm.startswith("HS"):
            token = sign_license(
                org_id=req.org_id,
                tier=req.tier,
                expires_at=req.expires_at,
                agent_limit=limit,
                metadata=req.metadata,
                hmac_secret=key,
                algorithm=_signing_algorithm,
            )
        else:
            token = sign_license(
                org_id=req.org_id,
                tier=req.tier,
                expires_at=req.expires_at,
                agent_limit=limit,
                metadata=req.metadata,
                private_key=key,
                algorithm=_signing_algorithm,
            )
    except Exception as exc:
        logger.error("license_sign_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"failed to sign license: {exc}",
        ) from exc

    now = datetime.now(UTC)
    license = License(
        org_id=req.org_id,
        tier=str(req.tier),
        agent_limit=limit,
        issued_at=now,
        expires_at=req.expires_at,
        signature=token.rsplit(".", 1)[-1],
        metadata=req.metadata,
    )
    logger.info("license_issued", org_id=req.org_id, tier=str(req.tier))
    return IssueLicenseResponse(jwt=token, license=license)


@router.get("/current", response_model=LicenseStatusResponse)
async def get_current_license(
    user: UserResponse = Depends(get_current_user),
) -> LicenseStatusResponse:
    """Return the current org's active license + agent usage."""
    if _current_license is None or _validator is None:
        return LicenseStatusResponse(
            license=None,
            status=LicenseStatus.INVALID,
            agents_used=_get_agent_count(),
            agents_limit=0,
            days_until_expiry=None,
        )
    stat = _validator.status(_current_license)
    return LicenseStatusResponse(
        license=_current_license,
        status=stat,
        agents_used=_get_agent_count(),
        agents_limit=_current_license.agent_limit,
        days_until_expiry=_validator.days_until_expiry(_current_license),
    )


@router.post("/validate", response_model=LicenseStatusResponse)
async def validate_license(
    req: ValidateLicenseRequest,
    user: UserResponse = Depends(get_current_user),
) -> LicenseStatusResponse:
    """Validate an arbitrary license JWT."""
    if _validator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="license validator not configured",
        )
    try:
        license = _validator.validate_license(req.jwt)
    except LicenseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    stat = _validator.status(license)
    return LicenseStatusResponse(
        license=license,
        status=stat,
        agents_used=0,
        agents_limit=license.agent_limit,
        days_until_expiry=_validator.days_until_expiry(license),
    )
