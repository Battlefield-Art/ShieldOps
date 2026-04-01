"""State models for the Behavioral Threat Detector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class BTDStage(StrEnum):
    """Stages of the behavioral threat detection lifecycle."""

    COLLECT_BEHAVIORS = "collect_behaviors"
    BUILD_BASELINES = "build_baselines"
    DETECT_DEVIATIONS = "detect_deviations"
    SCORE_THREATS = "score_threats"
    GENERATE_ALERTS = "generate_alerts"
    REPORT = "report"


class BehaviorSource(StrEnum):
    """Sources of behavioral data."""

    USER_ACTIVITY = "user_activity"
    NETWORK_TRAFFIC = "network_traffic"
    ENDPOINT_TELEMETRY = "endpoint_telemetry"
    APPLICATION_LOGS = "application_logs"
    AUTHENTICATION = "authentication"
    FILE_ACCESS = "file_access"
    DNS_QUERIES = "dns_queries"
    API_CALLS = "api_calls"


class DeviationType(StrEnum):
    """Types of behavioral deviations detected."""

    FREQUENCY_SPIKE = "frequency_spike"
    TIME_ANOMALY = "time_anomaly"
    GEO_ANOMALY = "geo_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    UNUSUAL_PROTOCOL = "unusual_protocol"
    CREDENTIAL_ABUSE = "credential_abuse"


class BehaviorRecord(BaseModel):
    """A single behavioral observation."""

    record_id: str = ""
    entity_id: str = ""
    entity_type: str = ""
    source: BehaviorSource = BehaviorSource.USER_ACTIVITY
    action: str = ""
    resource: str = ""
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    geo_location: str = ""
    session_id: str = ""


class BehaviorBaseline(BaseModel):
    """Behavioral baseline for an entity."""

    baseline_id: str = ""
    entity_id: str = ""
    source: BehaviorSource = BehaviorSource.USER_ACTIVITY
    avg_actions_per_hour: float = 0.0
    typical_hours: list[int] = Field(default_factory=list)
    typical_geos: list[str] = Field(default_factory=list)
    typical_resources: list[str] = Field(default_factory=list)
    std_deviation: float = 0.0
    sample_count: int = 0


class BehaviorDeviation(BaseModel):
    """A detected behavioral deviation."""

    deviation_id: str = ""
    entity_id: str = ""
    deviation_type: DeviationType = DeviationType.FREQUENCY_SPIKE
    severity: str = "medium"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = ""
    baseline_value: str = ""
    observed_value: str = ""
    evidence: list[str] = Field(default_factory=list)


class ThreatScore(BaseModel):
    """Threat score for an entity based on deviations."""

    score_id: str = ""
    entity_id: str = ""
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    deviation_count: int = 0
    highest_severity: str = "low"
    contributing_factors: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)


class ThreatAlert(BaseModel):
    """Alert generated from threat scoring."""

    alert_id: str = ""
    entity_id: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    deviations: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class BehavioralThreatDetectorState(BaseModel):
    """Full LangGraph state for the Behavioral Threat Detector."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: BTDStage = BTDStage.COLLECT_BEHAVIORS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    behaviors: list[dict[str, Any]] = Field(default_factory=list)
    baselines: list[dict[str, Any]] = Field(default_factory=list)
    deviations: list[dict[str, Any]] = Field(default_factory=list)
    threat_scores: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    entity_count: int = 0
    deviation_count: int = 0
    alert_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
