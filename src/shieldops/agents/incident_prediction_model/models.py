"""State models for the Incident Prediction Model Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class IPMStage(StrEnum):
    """Workflow stages for incident prediction model."""

    COLLECT_SIGNALS = "collect_signals"
    ANALYZE_PATTERNS = "analyze_patterns"
    BUILD_PREDICTIONS = "build_predictions"
    ASSESS_CONFIDENCE = "assess_confidence"
    RECOMMEND_PREVENTIONS = "recommend_preventions"
    REPORT = "report"


class SignalType(StrEnum):
    """Types of security signals for prediction."""

    ALERT = "alert"
    LOG_ANOMALY = "log_anomaly"
    METRIC_SPIKE = "metric_spike"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY = "vulnerability"
    BEHAVIORAL = "behavioral"
    CONFIGURATION = "configuration"


class PredictionConfidence(StrEnum):
    """Confidence levels for incident predictions."""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


# ── Domain Models ─────────────────────────────────────


class SecuritySignal(BaseModel):
    """A security signal used for prediction."""

    signal_id: str = ""
    signal_type: SignalType = SignalType.ALERT
    source: str = ""
    severity: str = ""
    timestamp: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    correlation_ids: list[str] = Field(default_factory=list)


class HistoricalPattern(BaseModel):
    """A pattern identified from historical incident data."""

    pattern_id: str = ""
    name: str = ""
    frequency: int = 0
    avg_impact: float = 0.0
    signal_types: list[str] = Field(default_factory=list)
    time_window_hours: int = 0
    last_occurrence: str = ""


class IncidentPrediction(BaseModel):
    """A predicted future incident."""

    prediction_id: str = ""
    title: str = ""
    predicted_type: str = ""
    probability: float = 0.0
    estimated_impact: str = ""
    time_horizon_hours: int = 0
    contributing_signals: list[str] = Field(default_factory=list)


class ConfidenceScore(BaseModel):
    """Confidence assessment for a prediction."""

    prediction_id: str = ""
    confidence: PredictionConfidence = PredictionConfidence.MEDIUM
    score: float = 0.0
    factors: list[str] = Field(default_factory=list)
    data_quality: float = 0.0


class PreventionPlan(BaseModel):
    """A prevention plan to avert a predicted incident."""

    plan_id: str = ""
    prediction_id: str = ""
    actions: list[str] = Field(default_factory=list)
    priority: str = ""
    estimated_effort_hours: float = 0.0
    risk_reduction: float = 0.0


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the prediction workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class IncidentPredictionModelState(BaseModel):
    """Full state for the Incident Prediction Model workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: IPMStage = IPMStage.COLLECT_SIGNALS
    config: dict[str, Any] = Field(default_factory=dict)

    signals: list[dict[str, Any]] = Field(default_factory=list)
    patterns: list[dict[str, Any]] = Field(default_factory=list)
    predictions: list[dict[str, Any]] = Field(default_factory=list)
    confidence_scores: list[dict[str, Any]] = Field(default_factory=list)
    prevention_plans: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
