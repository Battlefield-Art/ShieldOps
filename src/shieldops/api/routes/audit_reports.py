"""Audit report generation API routes."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from shieldops.api.auth.dependencies import require_role
from shieldops.security.audit_report_generator import (
    ReportFormat,
    ReportScope,
    ReportSection,
)

logger = structlog.get_logger()
router = APIRouter(
    prefix="/audit-reports",
    tags=["Audit Reports"],
)

_engine: Any = None


def set_engine(engine: Any) -> None:
    global _engine
    _engine = engine


def _get_engine() -> Any:
    if _engine is None:
        raise HTTPException(
            503,
            "Audit report generator service unavailable",
        )
    return _engine


# --- Request models ---


class GenerateReportRequest(BaseModel):
    agent_id: str = ""
    scope: ReportScope = ReportScope.SINGLE_AGENT
    format: ReportFormat = ReportFormat.JSON
    time_range_hours: int = 24
    include_sections: list[ReportSection] = []
    include_raw_data: bool = False
    compliance_framework: str | None = None
    firewall_data: dict[str, Any] = {}
    interceptor_data: dict[str, Any] = {}
    baseline_data: dict[str, Any] = {}


# --- Endpoints ---


@router.post("/generate")
async def generate_report(
    body: GenerateReportRequest,
    _user: Any = Depends(require_role("operator")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """Trigger audit report generation."""
    from shieldops.security.audit_report_generator import ReportConfig

    engine = _get_engine()
    config = ReportConfig(
        agent_id=body.agent_id,
        scope=body.scope,
        format=body.format,
        time_range_hours=body.time_range_hours,
        include_sections=body.include_sections or list(ReportSection),
        include_raw_data=body.include_raw_data,
        compliance_framework=body.compliance_framework,
    )
    result = engine.generate_report(
        config=config,
        firewall_data=body.firewall_data,
        interceptor_data=body.interceptor_data,
        baseline_data=body.baseline_data,
    )
    return result.model_dump()


@router.get("")
async def list_reports(
    scope: ReportScope | None = None,
    format: ReportFormat | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """List generated audit reports with optional filtering."""
    engine = _get_engine()
    records = engine._records[:]
    if scope is not None:
        records = [r for r in records if r.scope == scope]
    if format is not None:
        records = [r for r in records if r.format == format]
    total = len(records)
    page = records[offset : offset + limit]
    return {
        "items": [r.model_dump() for r in page],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """Get a specific audit report by ID."""
    engine = _get_engine()
    for record in engine._records:
        if record.id == report_id:
            return record.model_dump()
    raise HTTPException(404, f"Report '{report_id}' not found")


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """Download a report file. Returns report metadata with download info."""
    engine = _get_engine()
    for record in engine._records:
        if record.id == report_id:
            return {
                "id": record.id,
                "agent_id": record.agent_id,
                "format": record.format.value,
                "size_bytes": record.size_bytes,
                "generated_at": record.generated_at,
                "file_path": record.file_path,
                "download_url": f"/api/v1/audit-reports/{report_id}/file",
            }
    raise HTTPException(404, f"Report '{report_id}' not found")


@router.get("/summary/stats")
async def get_summary(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """Get audit report generation summary and statistics."""
    engine = _get_engine()
    return engine.generate_report_summary().model_dump()


@router.get("/stats/overview")
async def get_stats(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """Get quick statistics."""
    engine = _get_engine()
    return engine.get_stats()


@router.post("/clear")
async def clear_data(
    _user: Any = Depends(require_role("admin")),  # type: ignore[arg-type]
) -> dict[str, str]:
    """Clear all stored report records."""
    engine = _get_engine()
    return engine.clear_data()


data_route = router
