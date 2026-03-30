"""State models for the On-Call Optimizer Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OCOStage(StrEnum):
    """Stages in the on-call optimization workflow."""

    ANALYZE_SCHEDULES = "analyze_schedules"
    EVALUATE_LOAD = "evaluate_load"
    DETECT_BURNOUT = "detect_burnout"
    OPTIMIZE_ROTATION = "optimize_rotation"
    RECOMMEND_CHANGES = "recommend_changes"
    REPORT = "report"


class ShiftType(StrEnum):
    """On-call shift type classification."""

    PRIMARY = "primary"
    SECONDARY = "secondary"
    ESCALATION = "escalation"
    WEEKEND = "weekend"
    HOLIDAY = "holiday"
    FOLLOW_THE_SUN = "follow_the_sun"


class BurnoutRisk(StrEnum):
    """Burnout risk classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    HEALTHY = "healthy"


class OnCallOptimizerState(BaseModel):
    """Full state for the on-call optimizer workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: OCOStage = OCOStage.ANALYZE_SCHEDULES

    team_id: str = ""
    team_members: list[str] = Field(
        default_factory=list,
    )
    lookback_days: int = 90

    schedule_analysis: dict[str, Any] = Field(
        default_factory=dict,
    )
    load_evaluation: dict[str, Any] = Field(
        default_factory=dict,
    )
    burnout_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    optimized_rotation: dict[str, Any] = Field(
        default_factory=dict,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    current_step: str = ""
    error: str = ""
