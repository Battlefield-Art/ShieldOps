"""ROI Calculator API — projected savings vs traditional SIEM (#239)."""

from __future__ import annotations

import structlog
from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tools/roi-calculator", tags=["ROI Calculator"])

# Cost assumptions (override via config later)
SHIELDOPS_COST_PER_GB = 0.35  # USD / GB ingested
SIEM_COST_PER_GB_DEFAULT = 3.50
ANALYST_HOURLY_RATE = 95.0
HOURS_PER_YEAR = 2080


class ROIInput(BaseModel):
    current_siem_cost_usd: float = Field(..., ge=0, description="Current annual SIEM license cost")
    daily_log_volume_gb: float = Field(..., ge=0, description="Daily log ingestion volume in GB")
    soc_team_size: int = Field(..., ge=1, description="Number of full-time SOC analysts")
    avg_ir_time_min: float = Field(
        ..., ge=0, description="Current average incident response time (minutes)"
    )
    automation_rate: float = Field(
        0.75, ge=0, le=1, description="Fraction of incidents ShieldOps will auto-resolve"
    )


class ROIBreakdown(BaseModel):
    siem_savings_annual: float
    analyst_time_savings_annual: float
    faster_mttr_value_annual: float
    shieldops_cost_annual: float
    total_annual_savings: float
    payback_months: float


class ROIOutput(BaseModel):
    input: ROIInput
    breakdown: ROIBreakdown
    three_year_savings: float
    shareable_summary: str


@router.post("", response_model=ROIOutput)
async def calculate_roi(payload: ROIInput) -> ROIOutput:
    """Compute projected ROI vs the customer's current SIEM."""
    annual_gb = payload.daily_log_volume_gb * 365
    shieldops_cost = annual_gb * SHIELDOPS_COST_PER_GB
    siem_savings = max(0.0, payload.current_siem_cost_usd - shieldops_cost)

    # Analyst time saved: automation_rate * daily incidents * time saved
    incidents_per_day_est = max(1, int(payload.daily_log_volume_gb * 2))
    time_saved_per_incident_min = payload.avg_ir_time_min * payload.automation_rate
    analyst_hours_saved_annual = (incidents_per_day_est * time_saved_per_incident_min * 365) / 60
    analyst_savings = analyst_hours_saved_annual * ANALYST_HOURLY_RATE

    # MTTR faster -> reduced downtime cost (simplified)
    downtime_cost_per_hour = 5000.0
    mttr_reduction_hours_annual = (
        (incidents_per_day_est * 365) * (payload.avg_ir_time_min / 60) * 0.6
    )
    mttr_value = mttr_reduction_hours_annual * downtime_cost_per_hour * 0.1  # conservative

    total_savings = siem_savings + analyst_savings + mttr_value - shieldops_cost
    payback_months = (shieldops_cost / total_savings * 12) if total_savings > 0 else 0.0

    breakdown = ROIBreakdown(
        siem_savings_annual=siem_savings,
        analyst_time_savings_annual=analyst_savings,
        faster_mttr_value_annual=mttr_value,
        shieldops_cost_annual=shieldops_cost,
        total_annual_savings=total_savings,
        payback_months=round(payback_months, 1),
    )
    summary = (
        f"ShieldOps saves ~${total_savings:,.0f}/year with {payback_months:.1f}-month payback. "
        f"3-year savings: ${total_savings * 3:,.0f}."
    )
    logger.info("roi_calculator.computed", savings=total_savings, payback=payback_months)
    return ROIOutput(
        input=payload,
        breakdown=breakdown,
        three_year_savings=total_savings * 3,
        shareable_summary=summary,
    )
