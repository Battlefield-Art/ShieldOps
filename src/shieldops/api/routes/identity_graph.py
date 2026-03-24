"""Identity Graph API endpoints — identities, trust relationships, OAuth grants."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user, require_role
from shieldops.api.auth.models import UserResponse, UserRole

logger = structlog.get_logger()
router = APIRouter(prefix="/identity-graph", tags=["Identity Graph"])

_graph_engine: Any = None


def set_graph_engine(engine: Any) -> None:
    global _graph_engine
    _graph_engine = engine


# --- Request Models ---


class IdentityScanRequest(BaseModel):
    scope: str = "full"
    include_service_accounts: bool = True
    include_oauth_grants: bool = True
    include_trust_relationships: bool = True
    providers: list[str] = Field(default_factory=lambda: ["aws", "gcp", "azure", "okta"])


# --- Identity Endpoints ---


@router.get("/identities")
async def list_identities(
    identity_type: str | None = None,
    risk_level: str | None = None,
    provider: str | None = None,
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List identities in the graph."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    identities: list[dict[str, Any]] = await _graph_engine.list_identities(
        identity_type=identity_type,
        risk_level=risk_level,
        provider=provider,
        limit=limit,
    )
    return {"identities": identities, "total": len(identities)}


@router.get("/identities/{identity_id}")
async def get_identity_detail(
    identity_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get identity detail with relationships."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    identity: dict[str, Any] | None = await _graph_engine.get_identity(identity_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity


# --- Risk Endpoints ---


@router.get("/risks")
async def list_identity_risks(
    severity: str | None = None,
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List identity risks ordered by severity."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    risks: list[dict[str, Any]] = await _graph_engine.list_risks(
        severity=severity,
        limit=limit,
    )
    return {"risks": risks, "total": len(risks)}


# --- Trust Relationship Endpoints ---


@router.get("/trust-relationships")
async def list_trust_relationships(
    provider: str | None = None,
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List trust relationships between identity providers and accounts."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    relationships: list[dict[str, Any]] = await _graph_engine.list_trust_relationships(
        provider=provider,
        limit=limit,
    )
    return {"trust_relationships": relationships, "total": len(relationships)}


# --- OAuth Grant Endpoints ---


@router.get("/oauth-grants")
async def list_oauth_grants(
    risk_level: str | None = None,
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List OAuth grants with risk scores."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    grants: list[dict[str, Any]] = await _graph_engine.list_oauth_grants(
        risk_level=risk_level,
        limit=limit,
    )
    return {"oauth_grants": grants, "total": len(grants)}


# --- Scan Endpoint ---


@router.post("/scan")
async def trigger_identity_scan(
    body: IdentityScanRequest,
    _user: UserResponse = Depends(require_role(UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Trigger an identity graph discovery scan."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    scan_id = str(uuid.uuid4())
    result: dict[str, Any] = await _graph_engine.start_scan(
        scan_id=scan_id,
        scope=body.scope,
        include_service_accounts=body.include_service_accounts,
        include_oauth_grants=body.include_oauth_grants,
        include_trust_relationships=body.include_trust_relationships,
        providers=body.providers,
    )
    logger.info("identity_graph.scan_triggered", scan_id=scan_id, scope=body.scope)
    return {"scan_id": scan_id, **result}


# --- Metrics Endpoint ---


@router.get("/metrics")
async def identity_metrics(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get identity security metrics."""
    if _graph_engine is None:
        raise HTTPException(status_code=501, detail="Identity graph not configured")
    metrics: dict[str, Any] = await _graph_engine.get_metrics()
    metrics["timestamp"] = datetime.now(UTC).isoformat()
    return metrics
