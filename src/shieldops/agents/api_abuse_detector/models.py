"""State models for the API Abuse Detector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class AbuseStage(StrEnum):
    """Workflow stages for API abuse detection."""

    COLLECT_TRAFFIC = "collect_traffic"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_ABUSE = "detect_abuse"
    CLASSIFY_THREAT = "classify_threat"
    MITIGATE = "mitigate"
    REPORT = "report"


class AbuseThreatLevel(StrEnum):
    """Threat classification for detected abuse."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AbuseType(StrEnum):
    """Types of API abuse detected."""

    CREDENTIAL_STUFFING = "credential_stuffing"
    RATE_LIMIT_EVASION = "rate_limit_evasion"
    SCRAPING = "scraping"
    BOT_TRAFFIC = "bot_traffic"
    ENUMERATION = "enumeration"
    INJECTION = "injection"
    DATA_EXFILTRATION = "data_exfiltration"


# -- Domain Models -----------------------------------------------------


class TrafficSample(BaseModel):
    """A collected API traffic sample."""

    sample_id: str = ""
    endpoint: str = ""
    method: str = "GET"
    source_ip: str = ""
    user_agent: str = ""
    request_count: int = 0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AbusePattern(BaseModel):
    """A detected abuse pattern."""

    pattern_id: str = ""
    abuse_type: AbuseType = AbuseType.BOT_TRAFFIC
    endpoint: str = ""
    source_ips: list[str] = Field(default_factory=list)
    request_volume: int = 0
    time_window_secs: int = 0
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)


class ThreatClassification(BaseModel):
    """Threat classification for an abuse pattern."""

    pattern_id: str = ""
    threat_level: AbuseThreatLevel = AbuseThreatLevel.MEDIUM
    abuse_type: AbuseType = AbuseType.BOT_TRAFFIC
    business_impact: str = "low"
    mitre_technique: str = ""
    reasoning: str = ""


class MitigationAction(BaseModel):
    """A mitigation action applied to an abuse pattern."""

    action_id: str = ""
    pattern_id: str = ""
    action_type: str = "rate_limit"
    target: str = ""
    status: str = "pending"
    effectiveness: float = 0.0
    description: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the abuse detection workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ApiAbuseDetectorState(BaseModel):
    """Full state for the API Abuse Detector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: AbuseStage = AbuseStage.COLLECT_TRAFFIC
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Traffic collection
    traffic_samples: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_requests: int = 0

    # Pattern analysis
    abuse_patterns: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomaly_count: int = 0

    # Threat classification
    threat_classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_threat_level: str = "info"

    # Mitigation
    mitigations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blocked_sources: int = 0

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
