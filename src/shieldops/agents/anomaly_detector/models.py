"""Anomaly Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    COLLECT_DATA = "collect_data"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY = "classify"
    CORRELATE = "correlate"
    ALERT = "alert"
    REPORT = "report"


class AnomalyType(StrEnum):
    SPIKE = "spike"
    DROP = "drop"
    TREND_CHANGE = "trend_change"
    SEASONALITY_VIOLATION = "seasonality_violation"
    DISTRIBUTION_SHIFT = "distribution_shift"
    OUTLIER = "outlier"


class AnomalySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DataPoint(BaseModel):
    """A single metric/log/trace data point for anomaly analysis."""

    source: str = ""
    metric_name: str = ""
    value: float = 0.0
    timestamp: datetime | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    data_type: str = "metric"


class Anomaly(BaseModel):
    """A detected anomaly in telemetry data."""

    id: str = ""
    metric_name: str = ""
    anomaly_type: AnomalyType = AnomalyType.SPIKE
    baseline_value: float = 0.0
    current_value: float = 0.0
    deviation_sigma: float = 0.0
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    detected_at: datetime | None = None


class AnomalyCorrelation(BaseModel):
    """A correlation between multiple anomalies."""

    anomaly_ids: list[str] = Field(default_factory=list)
    correlation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    root_cause_hypothesis: str = ""
    affected_services: list[str] = Field(default_factory=list)


class AlertAction(BaseModel):
    """An alert action triggered by detected anomalies."""

    anomaly_id: str = ""
    action_type: str = ""
    channel: str = ""
    message: str = ""
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    acknowledged: bool = False


class AnomalyDetectorState(BaseModel):
    """Main state for the Anomaly Detector agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DetectionStage = DetectionStage.COLLECT_DATA

    # Collected data
    data_points: list[dict[str, Any]] = Field(default_factory=list)

    # Detected anomalies
    anomalies: list[dict[str, Any]] = Field(default_factory=list)

    # Correlations
    correlations: list[dict[str, Any]] = Field(default_factory=list)

    # Alerts
    alerts: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_data_points: int = 0
    total_anomalies: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
