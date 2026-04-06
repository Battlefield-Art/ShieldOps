"""Connector setup API routes.

Guided first-agent-run / onboarding wizard backend:

- POST   /api/v1/connectors/setup             -- store encrypted credentials
- GET    /api/v1/connectors                   -- list org connectors + health
- POST   /api/v1/connectors/{provider}/test   -- re-check connector health
- DELETE /api/v1/connectors/{provider}        -- remove an org connector

Credentials are encrypted at rest with ``cryptography.fernet`` using the
key from the ``SHIELDOPS_ENCRYPTION_KEY`` environment variable. The
encryption helper is exported so tests can exercise the round-trip.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()

router = APIRouter(prefix="/connectors", tags=["Connectors"])

# ── Supported providers ─────────────────────────────────────────────

SUPPORTED_PROVIDERS: dict[str, list[str]] = {
    "aws": ["access_key_id", "secret_access_key", "region"],
    "crowdstrike": ["client_id", "client_secret", "base_url"],
    "splunk": ["host", "token"],
}


# ── Encryption helpers ──────────────────────────────────────────────


def _get_fernet() -> Any:
    """Build a Fernet cipher from SHIELDOPS_ENCRYPTION_KEY (lazy import).

    Accepts either a url-safe base64-encoded 32-byte Fernet key, or any
    arbitrary string (hashed to a derived key). This keeps local dev
    simple while still supporting real rotation-friendly keys in prod.
    """
    from cryptography.fernet import Fernet  # lazy import

    raw = os.environ.get("SHIELDOPS_ENCRYPTION_KEY", "shieldops-dev-key-change-me")
    try:
        return Fernet(raw.encode() if isinstance(raw, str) else raw)
    except Exception:
        digest = hashlib.sha256(raw.encode()).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_credentials(credentials: dict[str, str]) -> str:
    """Encrypt a credentials dict to a url-safe ciphertext string."""
    fernet = _get_fernet()
    payload = json.dumps(credentials, sort_keys=True).encode("utf-8")
    return fernet.encrypt(payload).decode("utf-8")


def decrypt_credentials(ciphertext: str) -> dict[str, str]:
    """Decrypt a previously-encrypted credentials blob."""
    fernet = _get_fernet()
    raw = fernet.decrypt(ciphertext.encode("utf-8"))
    result = json.loads(raw.decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("decrypted credentials were not a JSON object")
    return {str(k): str(v) for k, v in result.items()}


# ── Repository injection ────────────────────────────────────────────

_repository: Any | None = None


def set_repository(repo: Any) -> None:
    """Set the repository instance used by these routes."""
    global _repository  # noqa: PLW0603
    _repository = repo


def _get_repo(request: Request) -> Any:
    repo = _repository or getattr(request.app.state, "repository", None)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )
    return repo


# ── Models ──────────────────────────────────────────────────────────


class ConnectorSetupRequest(BaseModel):
    provider: str = Field(..., description="Provider id, e.g. aws | crowdstrike | splunk")
    credentials: dict[str, str] = Field(..., description="Provider credential fields")
    model_config = {"extra": "forbid"}


class ConnectorInfo(BaseModel):
    id: str
    provider: str
    status: str
    last_health_check: str | None = None
    last_error: str = ""
    created_at: str | None = None


class ConnectorListResponse(BaseModel):
    connectors: list[ConnectorInfo]
    total: int


class HealthCheckResponse(BaseModel):
    provider: str
    status: str  # active | error
    message: str = ""
    checked_at: str


# ── Connector probes (mockable) ─────────────────────────────────────


async def _probe_connector(provider: str, credentials: dict[str, str]) -> tuple[bool, str]:
    """Light sanity-check of credentials without calling external APIs.

    Real network probes are intentionally avoided here so tests don't hit
    vendor services. Each connector's real ``connect()`` method can be
    wired in later behind a feature flag.
    """
    required = SUPPORTED_PROVIDERS.get(provider)
    if required is None:
        return False, f"unsupported provider: {provider}"
    missing = [f for f in required if not credentials.get(f)]
    if missing:
        return False, f"missing fields: {', '.join(missing)}"
    return True, "credentials accepted"


# ── Endpoints ───────────────────────────────────────────────────────


@router.post("/setup", response_model=ConnectorInfo)
async def setup_connector(
    request: Request,
    body: ConnectorSetupRequest,
    user: UserResponse = Depends(get_current_user),
) -> ConnectorInfo:
    """Test + encrypt + persist a connector for the caller's org."""
    if body.provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {body.provider}",
        )

    ok, message = await _probe_connector(body.provider, body.credentials)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Connector health check failed: {message}",
        )

    repo = _get_repo(request)
    org_id = getattr(user, "org_id", None) or "default"
    encrypted = encrypt_credentials(body.credentials)
    now = datetime.now(UTC)

    record = await repo.upsert_connector_config(
        org_id=org_id,
        provider=body.provider,
        encrypted_credentials=encrypted,
        status="active",
        last_health_check=now,
        last_error="",
    )

    logger.info(
        "connector_setup_completed",
        org_id=org_id,
        provider=body.provider,
        connector_id=record.get("id"),
    )
    return ConnectorInfo(
        id=record.get("id", ""),
        provider=body.provider,
        status="active",
        last_health_check=now.isoformat(),
        last_error="",
        created_at=record.get("created_at"),
    )


@router.get("", response_model=ConnectorListResponse)
async def list_connectors(
    request: Request,
    user: UserResponse = Depends(get_current_user),
) -> ConnectorListResponse:
    """List all connectors for the caller's org (no plaintext creds)."""
    repo = _get_repo(request)
    org_id = getattr(user, "org_id", None) or "default"
    records = await repo.list_connector_configs(org_id=org_id)
    connectors = [
        ConnectorInfo(
            id=r.get("id", ""),
            provider=r.get("provider", ""),
            status=r.get("status", "unknown"),
            last_health_check=r.get("last_health_check"),
            last_error=r.get("last_error", ""),
            created_at=r.get("created_at"),
        )
        for r in records
    ]
    return ConnectorListResponse(connectors=connectors, total=len(connectors))


@router.post("/{provider}/test", response_model=HealthCheckResponse)
async def test_connector(
    request: Request,
    provider: str,
    user: UserResponse = Depends(get_current_user),
) -> HealthCheckResponse:
    """Re-run the health check for a stored connector."""
    repo = _get_repo(request)
    org_id = getattr(user, "org_id", None) or "default"
    record = await repo.get_connector_config(org_id=org_id, provider=provider)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {provider} not configured for this org",
        )

    try:
        credentials = decrypt_credentials(record["encrypted_credentials"])
    except Exception as e:
        logger.error("connector_decrypt_failed", provider=provider, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt stored credentials",
        ) from e

    ok, message = await _probe_connector(provider, credentials)
    now = datetime.now(UTC)
    new_status = "active" if ok else "error"
    await repo.update_connector_config(
        org_id=org_id,
        provider=provider,
        status=new_status,
        last_health_check=now,
        last_error="" if ok else message,
    )

    return HealthCheckResponse(
        provider=provider,
        status=new_status,
        message=message,
        checked_at=now.isoformat(),
    )


@router.delete("/{provider}")
async def delete_connector(
    request: Request,
    provider: str,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Remove a connector configuration for the caller's org."""
    repo = _get_repo(request)
    org_id = getattr(user, "org_id", None) or "default"
    deleted = await repo.delete_connector_config(org_id=org_id, provider=provider)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {provider} not configured for this org",
        )
    logger.info("connector_deleted", org_id=org_id, provider=provider)
    return {"deleted": True, "provider": provider}
