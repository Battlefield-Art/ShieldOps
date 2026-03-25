"""Non-Human Identity (NHI) Registry API endpoints."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()
router = APIRouter(prefix="/nhi", tags=["NHI Registry"])

_registry_engine: Any = None
_posture_monitor: Any = None
_shadow_discovery: Any = None
_agent_runner: Any = None


def set_engines(
    registry_engine: Any = None,
    posture_monitor: Any = None,
    shadow_discovery: Any = None,
    agent_runner: Any = None,
) -> None:
    """Wire engine instances into the route module."""
    global _registry_engine, _posture_monitor, _shadow_discovery, _agent_runner
    _registry_engine = registry_engine
    _posture_monitor = posture_monitor
    _shadow_discovery = shadow_discovery
    _agent_runner = agent_runner


def _require_registry() -> Any:
    if _registry_engine is None:
        raise HTTPException(status_code=501, detail="NHI registry engine not configured")
    return _registry_engine


# --------------------------------------------------------------------------
# Health check
# --------------------------------------------------------------------------


@router.get("/health")
async def nhi_health() -> dict[str, Any]:
    """Health check for NHI Registry service."""
    components = {
        "registry": "ok" if _registry_engine else "not_initialized",
        "posture": "ok" if _posture_monitor else "not_initialized",
        "shadow_ai": "ok" if _shadow_discovery else "not_initialized",
    }
    all_ok = all(v == "ok" for v in components.values())
    return {
        "service": "nhi-registry",
        "status": "healthy" if all_ok else "degraded",
        "components": components,
        "timestamp": time.time(),
    }


# --------------------------------------------------------------------------
# Identity endpoints
# --------------------------------------------------------------------------


@router.get("/identities")
async def list_identities(
    query: str = "",
    nhi_type: str | None = None,
    status: str | None = None,
    provider: str | None = None,
    limit: int = Query(default=50, le=500),
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Search and filter the NHI registry."""
    engine = _require_registry()
    from shieldops.security.nhi_registry_engine import NHIStatus, NHIType

    nhi_type_enum = NHIType(nhi_type) if nhi_type else None
    status_enum = NHIStatus(status) if status else None
    results = engine.search(
        query=query,
        nhi_type=nhi_type_enum,
        status=status_enum,
        provider=provider,
        limit=limit,
    )
    return {
        "identities": [r.model_dump() for r in results],
        "total": len(results),
    }


@router.get("/identities/{identity_id}")
async def get_identity(
    identity_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get identity detail with risk score and activity."""
    engine = _require_registry()
    record = engine._find_record(identity_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    risk_score = engine.calculate_risk_score(identity_id, record=record)

    posture: dict[str, Any] = {}
    if _posture_monitor is not None:
        posture = _posture_monitor.evaluate_posture(identity_id)

    return {
        "identity": record.model_dump(),
        "risk_score": risk_score,
        "posture": posture,
    }


# --------------------------------------------------------------------------
# Scan endpoint
# --------------------------------------------------------------------------


@router.post("/scan")
async def trigger_scan(
    targets: list[str] | None = None,
    include_shadow_ai: bool = True,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Trigger an NHI discovery scan across cloud environments."""
    if _agent_runner is None:
        raise HTTPException(status_code=501, detail="NHI agent runner not configured")
    result = await _agent_runner.scan(
        targets=targets or [],
        include_shadow_ai=include_shadow_ai,
    )
    return {
        "status": "complete",
        "discovered": len(result.get("discovered_identities", [])),
        "shadow_ai": len(result.get("shadow_ai_agents", [])),
        "recommendations": len(result.get("remediation_recommendations", [])),
        "reasoning": result.get("reasoning_chain", []),
    }


# --------------------------------------------------------------------------
# Shadow AI
# --------------------------------------------------------------------------


@router.get("/shadow-ai")
async def list_shadow_ai(
    limit: int = Query(default=50, le=500),
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List detected shadow AI agents."""
    if _shadow_discovery is None:
        raise HTTPException(status_code=501, detail="Shadow AI discovery not configured")
    records = _shadow_discovery._records[-limit:]
    return {
        "shadow_ai_agents": [r.model_dump() for r in records],
        "total": len(records),
        "stats": _shadow_discovery.get_stats(),
    }


# --------------------------------------------------------------------------
# Risk-focused endpoints
# --------------------------------------------------------------------------


@router.get("/orphaned")
async def list_orphaned(
    stale_days: int = Query(default=90, ge=1),
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List orphaned identities with no owner or recent activity."""
    engine = _require_registry()
    orphaned = engine.detect_orphaned(stale_days=stale_days)
    return {
        "orphaned_identities": [r.model_dump() for r in orphaned],
        "total": len(orphaned),
        "stale_days_threshold": stale_days,
    }


@router.get("/over-privileged")
async def list_over_privileged(
    max_permissions: int = Query(default=10, ge=1),
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List over-privileged identities exceeding permission thresholds."""
    engine = _require_registry()
    over_priv = engine.detect_over_privileged(max_permissions=max_permissions)
    return {
        "over_privileged_identities": [r.model_dump() for r in over_priv],
        "total": len(over_priv),
        "max_permissions_threshold": max_permissions,
    }


# --------------------------------------------------------------------------
# Posture
# --------------------------------------------------------------------------


@router.get("/posture")
async def posture_summary(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Posture summary with health breakdown."""
    if _posture_monitor is None:
        raise HTTPException(status_code=501, detail="NHI posture monitor not configured")
    report = _posture_monitor.generate_report()
    return report.model_dump()


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


@router.get("/metrics")
async def nhi_metrics(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """NHI metrics: total, by type, by risk, orphaned count, shadow count."""
    engine = _require_registry()
    stats = engine.get_stats()

    shadow_count = 0
    if _shadow_discovery is not None:
        shadow_stats = _shadow_discovery.get_stats()
        shadow_count = shadow_stats.get("total_records", 0)

    report = engine.generate_report()
    return {
        "total_identities": stats["total_records"],
        "by_type": stats["nhi_type_distribution"],
        "by_risk": report.by_risk,
        "orphaned_count": stats["orphaned_count"],
        "over_privileged_count": stats["over_privileged_count"],
        "shadow_ai_count": shadow_count,
        "unique_providers": stats["unique_providers"],
        "unique_owners": stats["unique_owners"],
        "avg_risk_score": report.avg_risk_score,
    }
