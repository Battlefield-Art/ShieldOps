"""Situations API routes — outcome-centric security operations queue.

Provides paginated, filterable access to agent-generated situations
with drill-down detail and timeline support.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import require_role
from shieldops.api.auth.models import UserRole

logger = structlog.get_logger()
router = APIRouter(
    prefix="/situations",
    tags=["Situations"],
)

_engine: Any = None


def set_engine(engine: Any) -> None:
    global _engine
    _engine = engine


def _get_engine() -> Any:
    if _engine is None:
        raise HTTPException(503, "Situations service unavailable")
    return _engine


# ── Enums ─────────────────────────────────────────────────────────────


class SituationSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SituationStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    REMEDIATING = "remediating"
    REMEDIATED = "remediated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TimeRange(StrEnum):
    ONE_HOUR = "1h"
    TWENTY_FOUR_HOURS = "24h"
    SEVEN_DAYS = "7d"
    THIRTY_DAYS = "30d"


TIME_RANGE_DELTAS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


# ── Response Models ───────────────────────────────────────────────────


class TimelineEntry(BaseModel):
    """A single event in a situation's timeline."""

    id: str
    timestamp: str
    vendor: str = ""
    severity: str = "info"
    title: str
    description: str = ""
    technique: str = ""


class SituationSummary(BaseModel):
    """Compact situation for list views."""

    id: str
    title: str
    description: str = ""
    agent_name: str = ""
    type: str = ""
    severity: str = "medium"
    status: str = "new"
    vendors: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: int = 0
    correlated_events: int = 0
    time_open: str = ""
    primary_action: str = ""
    created_at: str = ""
    updated_at: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class SituationDetail(BaseModel):
    """Full situation with timeline for drill-down views."""

    id: str
    title: str
    description: str = ""
    agent_name: str = ""
    type: str = ""
    severity: str = "medium"
    status: str = "new"
    vendors: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    correlated_events: int = 0
    time_open: str = ""
    primary_action: str = ""
    ai_summary: str = ""
    blast_radius: str = ""
    created_at: str = ""
    updated_at: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)


class PaginatedSituationsResponse(BaseModel):
    """Paginated list of situations."""

    situations: list[SituationSummary]
    total: int
    limit: int
    offset: int


class SituationMetrics(BaseModel):
    """Aggregate metrics for the situations queue."""

    active_situations: int = 0
    avg_mttd_ms: int = 0
    avg_mtta_ms: int = 0
    avg_mttr_ms: int = 0
    auto_resolved_pct: float = 0.0
    actions_pending: int = 0
    total_sweeps: int = 0


# ── Request Models ────────────────────────────────────────────────────


class ExecuteActionRequest(BaseModel):
    """Request body for executing a recommended action."""

    confirm: bool = True
    override_reason: str = ""


class UpdateStatusRequest(BaseModel):
    """Request body for updating situation status."""

    status: str
    note: str = ""


# ── Helper: normalize situation dict to SituationSummary ─────────────


def _to_summary(sit: dict[str, Any]) -> SituationSummary:
    """Convert a raw situation dict (from engine) to a SituationSummary."""
    return SituationSummary(
        id=sit.get("situation_id", sit.get("id", "")),
        title=sit.get("title", ""),
        description=sit.get("description", ""),
        agent_name=sit.get("agent_name", sit.get("agent_type", "")),
        type=sit.get("type", sit.get("situation_type", "")),
        severity=sit.get("severity", "medium"),
        status=sit.get("status", "new"),
        vendors=sit.get("vendor_sources", sit.get("vendors", [])),
        mitre_techniques=sit.get("mitre_techniques", []),
        affected_assets=sit.get("affected_assets", 0)
        if isinstance(sit.get("affected_assets"), int)
        else len(sit.get("affected_assets", [])),
        correlated_events=sit.get("correlated_events", 0),
        time_open=sit.get("time_open", ""),
        primary_action=sit.get("primary_action", ""),
        created_at=str(sit.get("created_at", "")),
        updated_at=str(sit.get("updated_at", "")),
        details=sit.get("details", {}),
    )


def _to_detail(sit: dict[str, Any]) -> SituationDetail:
    """Convert a raw situation dict to a full SituationDetail."""
    affected = sit.get("affected_assets", [])
    if isinstance(affected, int):
        affected = [f"asset-{i}" for i in range(affected)]

    return SituationDetail(
        id=sit.get("situation_id", sit.get("id", "")),
        title=sit.get("title", ""),
        description=sit.get("description", ""),
        agent_name=sit.get("agent_name", sit.get("agent_type", "")),
        type=sit.get("type", sit.get("situation_type", "")),
        severity=sit.get("severity", "medium"),
        status=sit.get("status", "new"),
        vendors=sit.get("vendor_sources", sit.get("vendors", [])),
        mitre_techniques=sit.get("mitre_techniques", []),
        affected_assets=affected if isinstance(affected, list) else [],
        correlated_events=sit.get("correlated_events", 0),
        time_open=sit.get("time_open", ""),
        primary_action=sit.get("primary_action", ""),
        ai_summary=sit.get("ai_summary", ""),
        blast_radius=sit.get("blast_radius", ""),
        created_at=str(sit.get("created_at", "")),
        updated_at=str(sit.get("updated_at", "")),
        details=sit.get("details", {}),
        timeline=[
            TimelineEntry(**evt) if isinstance(evt, dict) else evt
            for evt in sit.get("timeline", [])
        ],
        recommended_actions=sit.get("recommended_actions", []),
    )


# ── Endpoints ─────────────────────────────────────────────────────────


@router.get("/health")
async def situations_health() -> dict[str, Any]:
    """Health check for Situations / SOC Brain service."""
    components: dict[str, str] = {
        "soc_brain": "ok" if _engine else "not_initialized",
    }
    all_ok = all(v == "ok" for v in components.values())
    return {
        "service": "situations",
        "status": "healthy" if all_ok else "degraded",
        "components": components,
        "timestamp": time.time(),
    }


@router.get("", response_model=PaginatedSituationsResponse)
async def list_situations(
    severity: str | None = Query(None, description="Filter by severity"),
    status: str | None = Query(None, description="Filter by status"),
    agent_name: str | None = Query(None, description="Filter by agent name/type"),
    vendor: str | None = Query(None, description="Filter by vendor source"),
    time_range: str | None = Query(None, description="Time window: 1h, 24h, 7d, 30d"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _user: Any = Depends(require_role(UserRole.VIEWER)),
) -> PaginatedSituationsResponse:
    """List situations with optional filters.

    Supports filtering by severity, status, agent_name, vendor, and time_range.
    Results are paginated with limit/offset.
    """
    engine = _get_engine()
    situations = await engine.get_active_situations()

    # Apply filters
    filtered = list(situations)
    if severity:
        filtered = [s for s in filtered if s.get("severity") == severity]
    if status:
        filtered = [s for s in filtered if s.get("status") == status]
    if agent_name:
        filtered = [
            s for s in filtered if agent_name in (s.get("agent_name", ""), s.get("agent_type", ""))
        ]
    if vendor:
        filtered = [s for s in filtered if vendor in s.get("vendor_sources", s.get("vendors", []))]
    if time_range and time_range in TIME_RANGE_DELTAS:
        cutoff = datetime.now(UTC) - TIME_RANGE_DELTAS[time_range]
        cutoff_ts = cutoff.timestamp()
        filtered = [s for s in filtered if _parse_created_at(s.get("created_at")) >= cutoff_ts]

    total = len(filtered)
    page = filtered[offset : offset + limit]

    return PaginatedSituationsResponse(
        situations=[_to_summary(s) for s in page],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/metrics", response_model=SituationMetrics)
async def get_situation_metrics(
    _user: Any = Depends(require_role(UserRole.VIEWER)),
) -> SituationMetrics:
    """Get MTTD/MTTA/MTTR metrics for situations."""
    engine = _get_engine()
    results = engine.list_results()

    total_situations = 0
    total_actions = 0
    total_mttd = 0
    total_mtta = 0
    total_mttr = 0
    count = max(len(results), 1)

    for r in results:
        total_situations += r.get("situations", 0)
        total_actions += r.get("actions_executed", 0)
        total_mttd += r.get("duration_ms", 0)
        total_mtta += r.get("duration_ms", 0)
        total_mttr += r.get("duration_ms", 0)

    return SituationMetrics(
        active_situations=total_situations,
        avg_mttd_ms=total_mttd // count,
        avg_mtta_ms=total_mtta // count,
        avg_mttr_ms=total_mttr // count,
        auto_resolved_pct=0.0
        if not total_situations
        else round(total_actions / total_situations * 100, 1),
        actions_pending=total_situations - total_actions,
        total_sweeps=len(results),
    )


@router.get("/{situation_id}", response_model=SituationDetail)
async def get_situation_detail(
    situation_id: str,
    _user: Any = Depends(require_role(UserRole.VIEWER)),
) -> SituationDetail:
    """Get detailed information about a specific situation including timeline."""
    engine = _get_engine()
    situations = await engine.get_active_situations()

    for sit in situations:
        if sit.get("situation_id") == situation_id or sit.get("id") == situation_id:
            return _to_detail(sit)

    raise HTTPException(404, f"Situation {situation_id} not found")


@router.post("/{situation_id}/actions/{action_id}/execute")
async def execute_action(
    situation_id: str,
    action_id: str,
    body: ExecuteActionRequest | None = None,
    _user: Any = Depends(require_role(UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Execute a recommended action for a situation."""
    engine = _get_engine()
    result = await engine.execute_action(situation_id, action_id)

    if result.get("error"):
        raise HTTPException(404, result["error"])

    logger.info(
        "situations.action_executed",
        situation_id=situation_id,
        action_id=action_id,
        status=result.get("status"),
    )
    return dict(result)


@router.put("/{situation_id}/status")
async def update_situation_status(
    situation_id: str,
    body: UpdateStatusRequest,
    _user: Any = Depends(require_role(UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Update the status of a situation."""
    engine = _get_engine()
    situations = await engine.get_active_situations()

    for sit in situations:
        if sit.get("situation_id") == situation_id or sit.get("id") == situation_id:
            sit["status"] = body.status
            logger.info(
                "situations.status_updated",
                situation_id=situation_id,
                new_status=body.status,
                note=body.note,
            )
            return {"situation_id": situation_id, "status": body.status}

    raise HTTPException(404, f"Situation {situation_id} not found")


# ── Internal Helpers ──────────────────────────────────────────────────


def _parse_created_at(value: Any) -> float:
    """Parse a created_at value to a unix timestamp for comparison."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value).timestamp()
        except (ValueError, TypeError):
            return 0.0
    return 0.0
