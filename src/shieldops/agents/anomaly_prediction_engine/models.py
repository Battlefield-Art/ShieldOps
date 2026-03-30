"""Anomaly Prediction Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class APEStage(StrEnum):
    INGEST_METRICS = "ingest_metrics"
    TRAIN_MODELS = "train_models"
    GENERATE_PREDICTIONS = "generate_predictions"
    VALIDATE_ACCURACY = "validate_accuracy"
    PUBLISH_ALERTS = "publish_alerts"
    REPORT = "report"


class MetricDomain(StrEnum):
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    SECURITY = "security"
    BUSINESS = "business"
    USER = "user"
    NETWORK = "network"


class PredictionConfidence(StrEnum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNCERTAIN = "uncertain"


class AnomalyPredictionEngineState(BaseModel):
    request_id: str = ""
    stage: APEStage = APEStage.INGEST_METRICS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
