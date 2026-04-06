"""CISO Dashboard API — MITRE heat map, top risks, vuln aging, audit readiness (#238)."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/dashboards/ciso", tags=["CISO Dashboard"])


class MitreTechnique(BaseModel):
    technique_id: str
    tactic: str
    count: int
    severity: str


class CisoMetrics(BaseModel):
    mitre_heatmap: list[MitreTechnique] = Field(default_factory=list)
    top_risks_by_bu: dict[str, float] = Field(default_factory=dict)
    vulnerability_aging: dict[str, int] = Field(default_factory=dict)
    audit_readiness: dict[str, float] = Field(default_factory=dict)
    range: str = "30d"


def _org(user: UserResponse) -> str:
    return (
        getattr(user, "org_id", None)
        or getattr(user, "tenant_id", None)
        or getattr(user, "id", "default")
    )


@router.get("", response_model=CisoMetrics)
async def get_ciso_metrics(
    time_range: str = Query("30d", alias="range", pattern="^(24h|7d|30d|90d)$"),
    user: UserResponse = Depends(get_current_user),
) -> CisoMetrics:
    """Strategic metrics for CISO dashboard."""
    logger.info("ciso_dashboard.fetch", org_id=_org(user), range=time_range)
    return CisoMetrics(
        mitre_heatmap=[
            MitreTechnique(
                technique_id="T1078", tactic="Initial Access", count=18, severity="high"
            ),
            MitreTechnique(
                technique_id="T1110", tactic="Credential Access", count=32, severity="medium"
            ),
            MitreTechnique(
                technique_id="T1566", tactic="Initial Access", count=12, severity="high"
            ),
            MitreTechnique(technique_id="T1059", tactic="Execution", count=24, severity="critical"),
            MitreTechnique(
                technique_id="T1055", tactic="Privilege Escalation", count=7, severity="critical"
            ),
        ],
        top_risks_by_bu={"engineering": 72.0, "finance": 81.0, "sales": 48.0, "hr": 55.0},
        vulnerability_aging={"lt_30d": 12, "30_60d": 8, "60_90d": 4, "gt_90d": 2},
        audit_readiness={"HIPAA": 94.0, "SOC2": 98.0, "PCI": 91.0, "ISO27001": 89.0},
        range=time_range,
    )


@router.get("/mitre/{technique_id}/findings")
async def drill_down_mitre(
    technique_id: str,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Drill down to findings for a specific MITRE technique."""
    logger.info("ciso_dashboard.drilldown", org_id=_org(user), technique=technique_id)
    return {
        "technique_id": technique_id,
        "findings": [
            {
                "id": f"{technique_id}-001",
                "severity": "high",
                "source": "crowdstrike",
                "seen_at": "2026-04-05T10:00:00Z",
            },
        ],
    }
