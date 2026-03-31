"""Alert Fatigue Reducer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AFRStage(StrEnum):
    COLLECT_ALERTS = "collect_alerts"
    ANALYZE_NOISE = "analyze_noise"
    DETECT_FATIGUE = "detect_fatigue"
    TUNE_RULES = "tune_rules"
    VALIDATE = "validate"
    REPORT = "report"


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NoiseCategory(StrEnum):
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"
    LOW_FIDELITY = "low_fidelity"
    STALE_RULE = "stale_rule"
    THRESHOLD_DRIFT = "threshold_drift"
    REDUNDANT = "redundant"


class AlertRecord(BaseModel):
    """A single alert record for analysis."""

    id: str = ""
    rule_id: str = ""
    rule_name: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    source: str = ""
    count_24h: int = 0
    count_7d: int = 0
    acknowledged_pct: float = 0.0
    avg_response_min: float = 0.0
    false_positive_rate: float = 0.0
    last_triggered: str = ""


class NoiseAnalysis(BaseModel):
    """Noise analysis for an alert rule."""

    id: str = ""
    rule_id: str = ""
    noise_category: NoiseCategory = NoiseCategory.DUPLICATE
    noise_score: float = 0.0
    signal_ratio: float = 0.0
    duplicate_count: int = 0
    correlation_group: str = ""
    recommendation: str = ""


class FatigueIndicator(BaseModel):
    """Fatigue indicator for an analyst or team."""

    id: str = ""
    analyst_id: str = ""
    team: str = ""
    alerts_per_shift: int = 0
    avg_triage_time_min: float = 0.0
    dismiss_rate: float = 0.0
    fatigue_score: float = 0.0
    burnout_risk: str = "low"
    top_noisy_rules: list[str] = Field(default_factory=list)


class TuningRule(BaseModel):
    """A suggested rule tuning action."""

    id: str = ""
    rule_id: str = ""
    action: str = ""
    current_threshold: str = ""
    suggested_threshold: str = ""
    expected_reduction_pct: float = 0.0
    risk_of_miss: float = 0.0
    rationale: str = ""


class ValidationResult(BaseModel):
    """Result of tuning validation."""

    id: str = ""
    rule_id: str = ""
    passed: bool = True
    alerts_before: int = 0
    alerts_after: int = 0
    reduction_pct: float = 0.0
    missed_true_positives: int = 0
    safe_to_deploy: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertFatigueReducerState(BaseModel):
    """Main state for the Alert Fatigue Reducer agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: AFRStage = AFRStage.COLLECT_ALERTS

    alerts: list[AlertRecord] = Field(default_factory=list)
    noise_analyses: list[NoiseAnalysis] = Field(default_factory=list)
    fatigue_indicators: list[FatigueIndicator] = Field(default_factory=list)
    tuning_rules: list[TuningRule] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)

    report: str = ""
    total_alerts_analyzed: int = 0
    noise_reduction_pct: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
