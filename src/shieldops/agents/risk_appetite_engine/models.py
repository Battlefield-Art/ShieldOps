"""State models for the Risk Appetite Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class RAEStage(StrEnum):
    """Workflow stages for risk appetite analysis."""

    DEFINE_APPETITE = "define_appetite"
    MEASURE_EXPOSURE = "measure_exposure"
    COMPARE_THRESHOLDS = "compare_thresholds"
    IDENTIFY_BREACHES = "identify_breaches"
    RECOMMEND_ADJUSTMENTS = "recommend_adjustments"
    REPORT = "report"


class RiskCategory(StrEnum):
    """Category of risk being assessed."""

    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    COMPLIANCE = "compliance"
    REPUTATIONAL = "reputational"
    STRATEGIC = "strategic"


class ToleranceLevel(StrEnum):
    """Tolerance level for risk."""

    ZERO = "zero"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    AGGRESSIVE = "aggressive"


# ── Domain Models ─────────────────────────────────────


class AppetiteDefinition(BaseModel):
    """Organization's risk appetite definition."""

    category: RiskCategory = RiskCategory.OPERATIONAL
    tolerance: ToleranceLevel = ToleranceLevel.MODERATE
    threshold_value: float = 0.0
    description: str = ""
    owner: str = ""


class ExposureMeasurement(BaseModel):
    """Measured risk exposure for a category."""

    category: RiskCategory = RiskCategory.OPERATIONAL
    current_value: float = 0.0
    trend: str = "stable"
    data_sources: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class ThresholdComparison(BaseModel):
    """Comparison of exposure against threshold."""

    category: RiskCategory = RiskCategory.OPERATIONAL
    threshold: float = 0.0
    actual: float = 0.0
    delta: float = 0.0
    within_tolerance: bool = True


class BreachRecord(BaseModel):
    """Record of a threshold breach."""

    breach_id: str = ""
    category: RiskCategory = RiskCategory.OPERATIONAL
    severity: str = "medium"
    overshoot_pct: float = 0.0
    duration_days: int = 0
    impact_summary: str = ""


class AdjustmentRecommendation(BaseModel):
    """Recommended adjustment to reduce risk."""

    recommendation_id: str = ""
    category: RiskCategory = RiskCategory.OPERATIONAL
    action: str = ""
    expected_reduction: float = 0.0
    effort: str = "medium"
    priority: int = 0


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the risk appetite workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class RiskAppetiteEngineState(BaseModel):
    """Full state for the Risk Appetite Engine workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: RAEStage = RAEStage.DEFINE_APPETITE
    config: dict[str, Any] = Field(default_factory=dict)

    appetite_definitions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposure_measurements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    threshold_comparisons: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    breach_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    adjustment_recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
