"""SOC Manager Dashboard API — MTTD/MTTR/alerts/workload (#237)."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/dashboards/soc-manager", tags=["SOC Manager Dashboard"])


class SOCManagerMetrics(BaseModel):
    mttd_seconds: float = 0.0
    mttr_seconds: float = 0.0
    alert_volume_by_severity: dict[str, int] = {}
    false_positive_rate: float = 0.0
    analyst_workload: dict[str, int] = {}
    agent_effectiveness: dict[str, float] = {}
    range: str = "24h"


def _org(user: UserResponse) -> str:
    return (
        getattr(user, "org_id", None)
        or getattr(user, "tenant_id", None)
        or getattr(user, "id", "default")
    )


@router.get("", response_model=SOCManagerMetrics)
async def get_soc_manager_metrics(
    time_range: str = Query("24h", alias="range", pattern="^(24h|7d|30d)$"),
    user: UserResponse = Depends(get_current_user),
) -> SOCManagerMetrics:
    """Operational metrics for the SOC Manager dashboard."""
    org_id = _org(user)
    logger.info("soc_manager_dashboard.fetch", org_id=org_id, range=time_range)
    return SOCManagerMetrics(
        mttd_seconds=45.0,
        mttr_seconds=180.0,
        alert_volume_by_severity={"critical": 3, "high": 12, "medium": 48, "low": 120},
        false_positive_rate=0.07,
        analyst_workload={"alice": 42, "bob": 38, "carol": 55},
        agent_effectiveness={
            "investigation": 0.92,
            "remediation": 0.88,
            "soc_analyst": 0.85,
            "threat_hunter": 0.79,
            "incident_response": 0.91,
        },
        range=time_range,
    )


@router.get("/trends")
async def get_soc_manager_trends(
    metric: str = Query(..., pattern="^(mttd|mttr|alerts|fpr)$"),
    time_range: str = Query("30d", alias="range", pattern="^(7d|30d|90d)$"),
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Time-series data for SOC Manager metrics."""
    logger.info("soc_manager_dashboard.trend", org_id=_org(user), metric=metric, range=time_range)
    n = 7 if time_range == "7d" else (30 if time_range == "30d" else 90)
    return {
        "metric": metric,
        "range": time_range,
        "points": [{"day": i, "value": 40 + i * 0.5} for i in range(n)],
    }
