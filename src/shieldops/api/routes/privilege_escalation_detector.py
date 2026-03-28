"""Privilege Escalation Detector API routes."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from shieldops.api.auth.dependencies import require_role

logger = structlog.get_logger()
router = APIRouter(
    prefix="/privilege-escalation-detector",
    tags=["Privilege Escalation Detector"],
)

_engine: Any = None


def set_engine(engine: Any) -> None:
    global _engine
    _engine = engine


def _get_engine() -> Any:
    if _engine is None:
        raise HTTPException(
            503,
            "Privilege escalation detector service unavailable",
        )
    return _engine


class RecordEscalationRequest(BaseModel):
    incident_id: str
    escalation_type: str = "sudo_abuse"
    principal_id: str = ""
    source_system: str = ""
    target_resource: str = ""
    previous_privilege: str = ""
    new_privilege: str = ""
    risk_score: float = 0.0
    model_config = {"extra": "forbid"}


class DetectRequest(BaseModel):
    tenant_id: str = ""
    time_window_hours: int = 24
    model_config = {"extra": "forbid"}


@router.post("/records")
async def record_escalation(
    body: RecordEscalationRequest,
    _user: Any = Depends(require_role("operator")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    engine = _get_engine()
    result = engine.add_record(**body.model_dump())
    return result.model_dump()


@router.get("/records")
async def list_escalations(
    escalation_type: str | None = None,
    source_system: str | None = None,
    limit: int = 50,
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> list[dict[str, Any]]:
    engine = _get_engine()
    records = engine.list_records(
        escalation_type=escalation_type,
        source_system=source_system,
        limit=limit,
    )
    return [r.model_dump() for r in records]


@router.get("/records/{record_id}")
async def get_escalation(
    record_id: str,
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    engine = _get_engine()
    result = engine.get_record(record_id)
    if result is None:
        raise HTTPException(
            404,
            f"Escalation record '{record_id}' not found",
        )
    return result.model_dump()


@router.get("/distribution")
async def analyze_escalation_distribution(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    engine = _get_engine()
    return engine.analyze_distribution()


@router.get("/high-risk")
async def identify_high_risk_escalations(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> list[dict[str, Any]]:
    engine = _get_engine()
    return engine.identify_high_risk()


@router.get("/risk-rankings")
async def rank_by_risk(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> list[dict[str, Any]]:
    engine = _get_engine()
    return engine.rank_by_risk_score()


@router.get("/trends")
async def escalation_trends(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    engine = _get_engine()
    return engine.detect_trends()


@router.get("/report")
async def generate_report(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    engine = _get_engine()
    return engine.generate_report().model_dump()


@router.get("/stats")
async def get_stats(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    engine = _get_engine()
    return engine.get_stats()


@router.post("/clear")
async def clear_data(
    _user: Any = Depends(require_role("operator")),  # type: ignore[arg-type]
) -> dict[str, str]:
    engine = _get_engine()
    return engine.clear_data()


privilege_escalation_detector_route = router
