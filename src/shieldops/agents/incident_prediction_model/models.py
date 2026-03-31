"""Incident Prediction Model Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IPMStage(StrEnum):
    COLLECT_INDICATORS = "collect_indicators"
    EXTRACT_FEATURES = "extract_features"
    RUN_MODEL = "run_model"
    ASSESS_CONFIDENCE = "assess_confidence"
    GENERATE_WARNINGS = "generate_warnings"
    REPORT = "report"


class IndicatorCategory(StrEnum):
    ANOMALY = "anomaly"
    BEHAVIORAL = "behavioral"
    VOLUMETRIC = "volumetric"
    SIGNATURE = "signature"
    ENVIRONMENTAL = "environmental"
    TEMPORAL = "temporal"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


class LeadingIndicator(BaseModel):
    """A leading indicator of a potential incident."""

    id: str = ""
    name: str = ""
    category: IndicatorCategory = IndicatorCategory.ANOMALY
    value: float = 0.0
    baseline_value: float = 0.0
    deviation: float = 0.0
    source: str = ""
    timestamp: str = ""


class FeatureVector(BaseModel):
    """Extracted feature vector for prediction."""

    id: str = ""
    indicator_id: str = ""
    features: dict[str, float] = Field(default_factory=dict)
    normalized: bool = False
    importance_score: float = 0.0


class PredictionResult(BaseModel):
    """Result from the prediction model."""

    id: str = ""
    incident_type: str = ""
    probability: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    time_horizon_hours: int = 24
    contributing_indicators: list[str] = Field(default_factory=list)
    model_version: str = "v1.0"


class ConfidenceAssessment(BaseModel):
    """Confidence assessment for a prediction."""

    id: str = ""
    prediction_id: str = ""
    model_confidence: float = 0.0
    data_quality_score: float = 0.0
    historical_accuracy: float = 0.0
    overall_confidence: float = 0.0
    caveats: list[str] = Field(default_factory=list)


class EarlyWarning(BaseModel):
    """An early warning generated from predictions."""

    id: str = ""
    prediction_id: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    expires_at: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentPredictionModelState(BaseModel):
    """Main state for the Incident Prediction Model agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: IPMStage = IPMStage.COLLECT_INDICATORS

    indicators: list[dict[str, Any]] = Field(default_factory=list)
    feature_vectors: list[dict[str, Any]] = Field(default_factory=list)
    predictions: list[dict[str, Any]] = Field(default_factory=list)
    confidence_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    warnings: list[dict[str, Any]] = Field(default_factory=list)

    report: str = ""
    total_indicators: int = 0
    predictions_generated: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
