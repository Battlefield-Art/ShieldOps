"""Executive Dashboard API — risk posture, cost savings, agent ROI, compliance (#236)."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/dashboards/executive", tags=["Executive Dashboard"])


class ExecutiveMetrics(BaseModel):
    risk_posture_score: float = Field(..., ge=0, le=100)
    risk_trend_percent: float = 0.0
    cost_savings_usd: float = 0.0
    cost_savings_vs_siem_percent: float = 0.0
    agent_roi_percent: float = Field(..., ge=0, le=100)
    incidents_auto_resolved: int = 0
    incidents_total: int = 0
    compliance: dict[str, float] = Field(default_factory=dict)
    range: str = "24h"


def _extract_org_id(user: UserResponse) -> str:
    return (
        getattr(user, "org_id", None)
        or getattr(user, "tenant_id", None)
        or getattr(user, "id", "default")
    )


@router.get("", response_model=ExecutiveMetrics)
async def get_executive_metrics(
    time_range: str = Query("24h", alias="range", pattern="^(24h|7d|30d|90d)$"),
    user: UserResponse = Depends(get_current_user),
) -> ExecutiveMetrics:
    """Snapshot of executive-level KPIs for an organization."""
    org_id = _extract_org_id(user)
    logger.info("executive_dashboard.fetch", org_id=org_id, range=time_range)
    return ExecutiveMetrics(
        risk_posture_score=72.0,
        risk_trend_percent=-5.2,
        cost_savings_usd=180_000.0,
        cost_savings_vs_siem_percent=68.0,
        agent_roi_percent=85.3,
        incidents_auto_resolved=141,
        incidents_total=165,
        compliance={"HIPAA": 94.0, "SOC2": 98.0, "PCI": 91.0, "GDPR": 96.0},
        range=time_range,
    )


@router.get("/trends")
async def get_executive_trends(
    metric: str = Query(..., pattern="^(risk|cost_savings|roi|compliance)$"),
    time_range: str = Query("30d", alias="range", pattern="^(7d|30d|90d)$"),
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Time-series data for a specific executive metric."""
    org_id = _extract_org_id(user)
    logger.info("executive_dashboard.trend", org_id=org_id, metric=metric, range=time_range)
    points = 7 if time_range == "7d" else (30 if time_range == "30d" else 90)
    if metric not in {"risk", "cost_savings", "roi", "compliance"}:
        raise HTTPException(status_code=400, detail="invalid metric")
    return {
        "metric": metric,
        "range": time_range,
        "points": [{"day": i, "value": 70 + i * 0.3} for i in range(points)],
    }
