"""State models for the Model Drift Detector Agent LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 3 StrEnums
# ---------------------------------------------------------------------------


class DriftStage(StrEnum):
    """Processing stages in the drift detection pipeline."""

    COLLECT = "collect"
    ANALYZE_DATA_DRIFT = "analyze_data_drift"
    ANALYZE_CONCEPT_DRIFT = "analyze_concept_drift"
    ANALYZE_PREDICTION_DRIFT = "analyze_prediction_drift"
    EVALUATE_THRESHOLDS = "evaluate_thresholds"
    REPORT = "report"
    COMPLETE = "complete"
    FAILED = "failed"


class DriftType(StrEnum):
    """Categories of model drift."""

    DATA_DRIFT = "data_drift"
    CONCEPT_DRIFT = "concept_drift"
    PREDICTION_DRIFT = "prediction_drift"
    FEATURE_DRIFT = "feature_drift"
    LABEL_DRIFT = "label_drift"
    COVARIATE_SHIFT = "covariate_shift"


class SeverityLevel(StrEnum):
    """Severity of detected drift."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class DriftMetric(BaseModel):
    """A single drift measurement for a feature or prediction."""

    feature_name: str = ""
    drift_type: str = DriftType.DATA_DRIFT
    statistic: str = ""
    baseline_value: float = 0.0
    current_value: float = 0.0
    drift_score: float = 0.0
    threshold: float = 0.0
    exceeded: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DriftAlert(BaseModel):
    """An alert triggered by detected drift."""

    alert_id: str = ""
    model_id: str = ""
    drift_type: str = DriftType.DATA_DRIFT
    severity: str = SeverityLevel.LOW
    feature_name: str = ""
    drift_score: float = 0.0
    message: str = ""
    retrain_recommended: bool = False
    timestamp: datetime | None = None


class ReasoningStep(BaseModel):
    """Audit trail entry for the drift detection workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------


class ModelDriftDetectorState(BaseModel):
    """Full state for a model drift detection workflow run."""

    # Input
    tenant_id: str = ""
    run_id: str = ""
    model_ids: list[str] = Field(default_factory=list)

    # Collection
    collected_metrics: list[dict[str, Any]] = Field(default_factory=list)

    # Analysis
    data_drift_results: list[dict[str, Any]] = Field(default_factory=list)
    concept_drift_results: list[dict[str, Any]] = Field(default_factory=list)
    prediction_drift_results: list[dict[str, Any]] = Field(default_factory=list)

    # Alerts
    alerts: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Summary metrics
    total_models: int = 0
    total_features_checked: int = 0
    total_drifts_detected: int = 0
    retrain_recommended: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
