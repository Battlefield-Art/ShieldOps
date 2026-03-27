"""State models for the Autonomous SOC Agent LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SOCStage(StrEnum):
    """Stages in the autonomous SOC pipeline."""

    INGEST_EVENTS = "ingest_events"
    ML_DETECT_ANOMALIES = "ml_detect_anomalies"
    CORRELATE_INCIDENTS = "correlate_incidents"
    AUTO_TRIAGE = "auto_triage"
    ORCHESTRATE_RESPONSE = "orchestrate_response"
    MEASURE_OUTCOMES = "measure_outcomes"
    REPORT = "report"


class AutomationLevel(StrEnum):
    """Automation level for SOC operations."""

    FULLY_AUTONOMOUS = "fully_autonomous"
    SUPERVISED = "supervised"
    MANUAL = "manual"
    DISABLED = "disabled"


class IncidentPriority(StrEnum):
    """Incident priority classification."""

    P0_CRITICAL = "p0_critical"
    P1_HIGH = "p1_high"
    P2_MEDIUM = "p2_medium"
    P3_LOW = "p3_low"
    P4_INFO = "p4_info"


class SecurityEvent(BaseModel):
    """Normalized security event from any SIEM source."""

    event_id: str = ""
    source_siem: str = ""
    original_id: str = ""
    event_type: str = ""
    severity: str = "medium"
    timestamp: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    hostname: str = ""
    user: str = ""
    description: str = ""
    mitre_technique: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0
    ingested_at: str = ""


class AnomalyDetection(BaseModel):
    """Result of statistical + LLM anomaly detection."""

    anomaly_id: str = ""
    event_ids: list[str] = Field(default_factory=list)
    anomaly_type: str = ""
    description: str = ""
    statistical_score: float = 0.0
    llm_score: float = 0.0
    combined_score: float = 0.0
    baseline_deviation: float = 0.0
    affected_entities: list[str] = Field(
        default_factory=list,
    )
    detection_method: str = ""
    is_anomalous: bool = False


class IncidentCorrelation(BaseModel):
    """Correlated incident from multiple anomalies/events."""

    incident_id: str = ""
    anomaly_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    title: str = ""
    description: str = ""
    priority: IncidentPriority = IncidentPriority.P2_MEDIUM
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )
    affected_assets: list[str] = Field(
        default_factory=list,
    )
    kill_chain_phase: str = ""
    confidence: float = 0.0
    siem_sources: list[str] = Field(default_factory=list)
    created_at: str = ""


class TriageDecision(BaseModel):
    """Auto-triage decision with confidence-based automation."""

    incident_id: str = ""
    priority: IncidentPriority = IncidentPriority.P2_MEDIUM
    automation_level: AutomationLevel = AutomationLevel.MANUAL
    confidence: float = 0.0
    reasoning: str = ""
    assigned_to: str = ""
    escalation_needed: bool = False
    escalation_reason: str = ""
    recommended_playbook: str = ""
    estimated_impact: str = ""


class ResponseOrchestration(BaseModel):
    """Multi-step response orchestration result."""

    response_id: str = ""
    incident_id: str = ""
    playbook_name: str = ""
    steps_executed: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    steps_pending: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    status: str = "pending"
    automation_level: AutomationLevel = AutomationLevel.SUPERVISED
    started_at: str = ""
    completed_at: str = ""
    outcome: str = ""
    error: str = ""


class OutcomeMeasurement(BaseModel):
    """SOC performance outcome measurement."""

    measurement_id: str = ""
    incident_id: str = ""
    mttd_seconds: float = 0.0
    mttr_seconds: float = 0.0
    automation_rate: float = 0.0
    false_positive: bool = False
    analyst_override: bool = False
    outcome_category: str = ""
    feedback: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the Autonomous SOC workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutonomousSOCState(BaseModel):
    """Full state for the Autonomous SOC LangGraph workflow."""

    # Input
    tenant_id: str = ""
    siem_sources: list[str] = Field(
        default_factory=list,
    )
    time_range_minutes: int = 60
    automation_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Ingestion
    security_events: list[SecurityEvent] = Field(
        default_factory=list,
    )
    events_processed: int = 0

    # Anomaly detection
    anomalies: list[AnomalyDetection] = Field(
        default_factory=list,
    )
    anomalies_detected: int = 0

    # Incident correlation
    incidents: list[IncidentCorrelation] = Field(
        default_factory=list,
    )
    incidents_created: int = 0

    # Triage
    triage_decisions: list[TriageDecision] = Field(
        default_factory=list,
    )
    auto_triaged: int = 0

    # Response
    responses: list[ResponseOrchestration] = Field(
        default_factory=list,
    )
    responses_orchestrated: int = 0

    # Outcomes
    outcomes: list[OutcomeMeasurement] = Field(
        default_factory=list,
    )

    # Metrics
    mean_time_to_detect_seconds: float = 0.0
    mean_time_to_respond_seconds: float = 0.0
    automation_rate: float = 0.0
    false_positive_rate: float = 0.0

    # Workflow tracking
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_stage: str = "init"
    session_id: str = ""
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""

    # Report
    report: dict[str, Any] = Field(
        default_factory=dict,
    )
