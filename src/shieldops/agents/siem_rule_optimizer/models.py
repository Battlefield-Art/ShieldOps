"""State models for the SIEM Rule Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SROStage(StrEnum):
    """Stages in the SIEM rule optimization lifecycle."""

    COLLECT_RULES = "collect_rules"
    ANALYZE_PERFORMANCE = "analyze_performance"
    DETECT_OVERLAP = "detect_overlap"
    TUNE_THRESHOLDS = "tune_thresholds"
    VALIDATE = "validate"
    REPORT = "report"


class RuleCategory(StrEnum):
    """Category of a SIEM detection rule."""

    CORRELATION = "correlation"
    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    AGGREGATION = "aggregation"


class PerformanceRating(StrEnum):
    """Performance rating of a detection rule."""

    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"
    DISABLED = "disabled"


# --- Domain models ---


class DetectionRule(BaseModel):
    """A SIEM detection rule subject to optimization."""

    rule_id: str = ""
    name: str = ""
    category: RuleCategory = RuleCategory.CORRELATION
    source_siem: str = ""
    query: str = ""
    threshold: float = 0.0
    severity: str = "medium"
    enabled: bool = True
    mitre_technique: str = ""


class RulePerformance(BaseModel):
    """Performance metrics for a detection rule."""

    rule_id: str = ""
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    avg_latency_ms: float = 0.0
    alert_volume_24h: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


class RuleOverlap(BaseModel):
    """Detected overlap between two detection rules."""

    overlap_id: str = ""
    rule_a_id: str = ""
    rule_b_id: str = ""
    overlap_pct: float = 0.0
    recommendation: str = ""
    alert_savings: int = 0


class ThresholdTuning(BaseModel):
    """Proposed threshold tuning for a detection rule."""

    rule_id: str = ""
    current_threshold: float = 0.0
    recommended_threshold: float = 0.0
    expected_fp_reduction: float = 0.0
    expected_fn_increase: float = 0.0
    rationale: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the optimizer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SIEMRuleOptimizerState(BaseModel):
    """Full state for a SIEM rule optimizer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SROStage = SROStage.COLLECT_RULES

    # Inputs
    siem_source: str = ""
    rule_filters: dict[str, Any] = Field(
        default_factory=dict,
    )
    optimization_config: dict[str, Any] = Field(
        default_factory=dict,
    )
    time_range: str = "30d"

    # Pipeline fields
    rules: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    performance_data: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    overlaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    tuning_suggestions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validation_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_rules: int = 0
    rules_optimized: int = 0
    fp_reduction_pct: float = 0.0
    overlap_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
