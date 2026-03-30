"""State models for the Log Anomaly Detector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class LADStage(StrEnum):
    """Workflow stages for log anomaly detection."""

    INGEST_LOGS = "ingest_logs"
    PARSE_PATTERNS = "parse_patterns"
    DETECT_ANOMALIES = "detect_anomalies"
    CORRELATE = "correlate"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class AnomalyType(StrEnum):
    """Types of log anomalies detected."""

    FREQUENCY_SPIKE = "frequency_spike"
    NEW_PATTERN = "new_pattern"
    MISSING_EVENT = "missing_event"
    SEQUENCE_BREAK = "sequence_break"
    VOLUME_ANOMALY = "volume_anomaly"
    CONTENT_ANOMALY = "content_anomaly"
    TIMING_ANOMALY = "timing_anomaly"


class LogSource(StrEnum):
    """Sources of log data for ingestion."""

    SYSLOG = "syslog"
    APPLICATION = "application"
    SECURITY = "security"
    AUDIT = "audit"
    CLOUD_TRAIL = "cloud_trail"
    CONTAINER = "container"
    NETWORK = "network"


# ── Domain Models ─────────────────────────────────────


class IngestedLog(BaseModel):
    """A batch of ingested log data."""

    batch_id: str = ""
    source: LogSource = LogSource.APPLICATION
    record_count: int = 0
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    size_bytes: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogPattern(BaseModel):
    """An extracted log pattern from parsed data."""

    pattern_id: str = ""
    template: str = ""
    frequency: int = 0
    source: str = ""
    is_new: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sample_messages: list[str] = Field(default_factory=list)


class DetectedAnomaly(BaseModel):
    """An anomaly detected in log data."""

    anomaly_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.FREQUENCY_SPIKE
    severity: str = "medium"
    confidence: float = 0.0
    source: str = ""
    description: str = ""
    affected_patterns: list[str] = Field(
        default_factory=list,
    )
    evidence: dict[str, Any] = Field(default_factory=dict)


class CorrelatedEvent(BaseModel):
    """A correlated event linking multiple anomalies."""

    correlation_id: str = ""
    anomaly_ids: list[str] = Field(default_factory=list)
    correlation_score: float = 0.0
    description: str = ""
    root_cause_hypothesis: str = ""
    affected_systems: list[str] = Field(
        default_factory=list,
    )


class PrioritizedAlert(BaseModel):
    """A prioritized alert from anomaly detection."""

    alert_id: str = ""
    title: str = ""
    priority: str = "medium"
    anomaly_ids: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    false_positive_likelihood: float = 0.0
    description: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the detector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class LogAnomalyDetectorState(BaseModel):
    """Full state for the Log Anomaly Detector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: LADStage = LADStage.INGEST_LOGS
    detect_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Ingestion
    ingested_logs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_records: int = 0

    # Patterns
    log_patterns: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    new_pattern_count: int = 0

    # Anomalies
    detected_anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_anomaly_score: float = 0.0

    # Correlations
    correlated_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Alerts
    prioritized_alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
