"""State models for the Log Intelligence Agent LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class LogStage(StrEnum):
    """Stages in the log intelligence pipeline."""

    INGEST_LOGS = "ingest_logs"
    PARSE_AND_NORMALIZE = "parse_and_normalize"
    DETECT_PATTERNS = "detect_patterns"
    CORRELATE_THREATS = "correlate_threats"
    GENERATE_INSIGHTS = "generate_insights"
    REPORT = "report"


class LogSource(StrEnum):
    """Supported log source platforms."""

    SPLUNK = "splunk"
    ELASTIC = "elastic"
    CLOUDWATCH = "cloudwatch"
    GCP_LOGGING = "gcp_logging"
    DATADOG = "datadog"
    SYSLOG = "syslog"
    CUSTOM = "custom"


class PatternType(StrEnum):
    """Types of patterns detected in log data."""

    ANOMALY = "anomaly"
    SECURITY_EVENT = "security_event"
    ERROR_SPIKE = "error_spike"
    BEHAVIORAL = "behavioral"
    COMPLIANCE = "compliance"


class LogBatch(BaseModel):
    """A batch of raw logs ingested from a source."""

    id: str = ""
    source: LogSource = LogSource.CUSTOM
    raw_count: int = 0
    time_start: float = 0.0
    time_end: float = 0.0
    services: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedLog(BaseModel):
    """A log entry normalized to a common schema."""

    id: str = ""
    source: LogSource = LogSource.CUSTOM
    timestamp: float = 0.0
    severity: str = ""
    service: str = ""
    message: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)
    original_format: str = ""


class PatternDetection(BaseModel):
    """A pattern detected across normalized logs."""

    id: str = ""
    pattern_type: PatternType = PatternType.ANOMALY
    description: str = ""
    frequency: int = 0
    severity: str = "medium"
    affected_services: list[str] = Field(default_factory=list)
    sample_messages: list[str] = Field(default_factory=list)
    baseline_deviation_pct: float = 0.0
    confidence: float = 0.0


class ThreatCorrelation(BaseModel):
    """A threat correlation linking patterns to attack indicators."""

    id: str = ""
    pattern_ids: list[str] = Field(default_factory=list)
    threat_category: str = ""
    mitre_technique: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    ioc_matches: list[str] = Field(default_factory=list)
    recommended_action: str = ""


class LogInsight(BaseModel):
    """An actionable insight generated from log analysis."""

    id: str = ""
    title: str = ""
    description: str = ""
    insight_type: str = ""
    priority: str = "medium"
    affected_services: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the log intelligence workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class LogIntelligenceState(BaseModel):
    """Full state for a log intelligence workflow run."""

    # Input
    tenant_id: str = ""
    sources: list[LogSource] = Field(default_factory=list)
    time_range_hours: int = 24
    query: str = ""

    # Stage tracking
    stage: LogStage = LogStage.INGEST_LOGS

    # Ingestion
    batches: list[LogBatch] = Field(default_factory=list)
    logs_ingested: int = 0

    # Normalization
    normalized_logs: list[NormalizedLog] = Field(default_factory=list)
    normalization_errors: int = 0

    # Pattern detection
    patterns_detected: list[PatternDetection] = Field(default_factory=list)
    max_severity: str = "info"

    # Threat correlation
    threats_correlated: list[ThreatCorrelation] = Field(default_factory=list)

    # Insights
    insights_generated: list[LogInsight] = Field(default_factory=list)

    # Performance
    query_performance_ms: int = 0

    # Report
    report_summary: str = ""

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
