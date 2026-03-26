"""State models for the Log Analyzer Agent LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalyzerStage(StrEnum):
    """Stages in the log analysis pipeline."""

    COLLECT_LOGS = "collect_logs"
    PARSE_PATTERNS = "parse_patterns"
    DETECT_ANOMALIES = "detect_anomalies"
    CORRELATE_EVENTS = "correlate_events"
    ALERT = "alert"
    REPORT = "report"


class LogSource(StrEnum):
    """Log source categories."""

    APPLICATION = "application"
    SYSTEM = "system"
    SECURITY = "security"
    NETWORK = "network"
    KUBERNETES = "kubernetes"


class AnomalySeverity(StrEnum):
    """Severity levels for detected anomalies."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogPattern(BaseModel):
    """A recurring pattern identified in log data."""

    id: str = ""
    source: LogSource = LogSource.APPLICATION
    pattern: str = ""
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_error: bool = False
    service: str = ""


class LogAnomaly(BaseModel):
    """An anomaly detected via statistical deviation from baseline."""

    id: str = ""
    source: LogSource = LogSource.APPLICATION
    anomaly_type: str = ""
    description: str = ""
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    baseline_count: int = 0
    current_count: int = 0
    deviation_pct: float = 0.0
    sample_logs: list[str] = Field(default_factory=list)


class EventCorrelation(BaseModel):
    """A correlation linking multiple anomalies to a potential root cause."""

    id: str = ""
    anomaly_ids: list[str] = Field(default_factory=list)
    correlation_type: str = ""
    description: str = ""
    root_cause_hypothesis: str = ""
    confidence: float = 0.0


class ReasoningStep(BaseModel):
    """Audit trail entry for the log analyzer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class LogAnalyzerState(BaseModel):
    """Full state for a log analyzer workflow run through the LangGraph workflow."""

    # Input
    tenant_id: str = ""
    sources: list[LogSource] = Field(default_factory=list)
    time_range_hours: int = 24

    # Stage tracking
    stage: AnalyzerStage = AnalyzerStage.COLLECT_LOGS

    # Collected data
    log_samples: list[dict[str, Any]] = Field(default_factory=list)
    total_log_count: int = 0

    # Pattern analysis
    patterns: list[LogPattern] = Field(default_factory=list)
    error_pattern_count: int = 0

    # Anomaly detection
    anomalies: list[LogAnomaly] = Field(default_factory=list)
    max_severity: AnomalySeverity = AnomalySeverity.INFO

    # Event correlation
    correlations: list[EventCorrelation] = Field(default_factory=list)

    # Alerting
    alerts_sent: int = 0
    alert_channels: list[str] = Field(default_factory=list)

    # Report
    report_summary: str = ""

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
