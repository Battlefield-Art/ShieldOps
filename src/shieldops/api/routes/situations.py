"""Situations API routes — outcome-centric security operations."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

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
        raise HTTPException(
            503,
            "Situations service unavailable",
        )
    return _engine


class ExecuteActionRequest(BaseModel):
    """Request body for executing a recommended action."""

    confirm: bool = True
    override_reason: str = ""


class UpdateStatusRequest(BaseModel):
    """Request body for updating situation status."""

    status: str
    note: str = ""


@router.get("")
async def list_situations(
    severity: str | None = Query(None, description="Filter by severity"),
    status: str | None = Query(None, description="Filter by status"),
    vendor: str | None = Query(None, description="Filter by vendor source"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _user: Any = Depends(require_role(UserRole.VIEWER)),
) -> dict[str, Any]:
    """List situations with optional filters."""
    engine = _get_engine()
    situations = await engine.get_active_situations()

    # Apply filters
    filtered = situations
    if severity:
        filtered = [s for s in filtered if s.get("severity") == severity]
    if status:
        filtered = [s for s in filtered if s.get("status") == status]
    if vendor:
        filtered = [s for s in filtered if vendor in s.get("vendor_sources", [])]

    total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "situations": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/metrics")
async def get_situation_metrics(
    _user: Any = Depends(require_role(UserRole.VIEWER)),
) -> dict[str, Any]:
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

    return {
        "active_situations": total_situations,
        "avg_mttd_ms": total_mttd // count,
        "avg_mtta_ms": total_mtta // count,
        "avg_mttr_ms": total_mttr // count,
        "auto_resolved_pct": 0.0
        if not total_situations
        else round(total_actions / total_situations * 100, 1),
        "actions_pending": total_situations - total_actions,
        "total_sweeps": len(results),
    }


@router.get("/{situation_id}")
async def get_situation_detail(
    situation_id: str,
    _user: Any = Depends(require_role(UserRole.VIEWER)),
) -> dict[str, Any]:
    """Get detailed information about a specific situation."""
    engine = _get_engine()
    situations = await engine.get_active_situations()

    for sit in situations:
        if sit.get("situation_id") == situation_id:
            return {"situation": sit}

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
        if sit.get("situation_id") == situation_id:
            sit["status"] = body.status
            logger.info(
                "situations.status_updated",
                situation_id=situation_id,
                new_status=body.status,
                note=body.note,
            )
            return {"situation_id": situation_id, "status": body.status}

    raise HTTPException(404, f"Situation {situation_id} not found")
