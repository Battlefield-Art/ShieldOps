"""State models for the SOC Brain Agent LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TriggerType(StrEnum):
    """How the SOC Brain workflow was initiated."""

    ALERT = "alert"
    INCIDENT = "incident"
    SCHEDULED = "scheduled"
    MANUAL = "manual"


class SituationSeverity(StrEnum):
    """Severity classification for a situation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SituationStatus(StrEnum):
    """Lifecycle status of a situation."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    REMEDIATING = "remediating"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class ActionType(StrEnum):
    """Type of response action."""

    INVESTIGATE = "investigate"
    CONTAIN = "contain"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"
    NOTIFY = "notify"


class NormalizedEvent(BaseModel):
    """Vendor-agnostic normalized security event."""

    event_id: str = ""
    vendor: str = ""
    original_id: str = ""
    event_type: str = ""
    severity: str = "low"
    timestamp: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    hostname: str = ""
    user: str = ""
    description: str = ""
    mitre_technique: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0


class CorrelatedFinding(BaseModel):
    """A set of events that have been correlated across vendors."""

    finding_id: str = ""
    event_ids: list[str] = Field(default_factory=list)
    vendors: list[str] = Field(default_factory=list)
    correlation_type: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)


class Situation(BaseModel):
    """An actionable situation — the core unit of the outcome-centric UX."""

    situation_id: str = ""
    title: str = ""
    description: str = ""
    severity: SituationSeverity = SituationSeverity.MEDIUM
    status: SituationStatus = SituationStatus.NEW
    finding_ids: list[str] = Field(default_factory=list)
    vendor_sources: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phase: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    correlated_event_count: int = 0
    blast_radius: str = ""
    ai_summary: str = ""
    created_at: str = ""
    updated_at: str = ""


class RecommendedAction(BaseModel):
    """An action recommended by the SOC Brain for a situation."""

    action_id: str = ""
    situation_id: str = ""
    action_type: ActionType = ActionType.INVESTIGATE
    vendor: str = ""
    target: str = ""
    description: str = ""
    confidence: float = 0.0
    auto_approved: bool = False
    risk_level: str = "medium"
    estimated_impact: str = ""


class ExecutedAction(BaseModel):
    """An action that has been executed."""

    action_id: str = ""
    situation_id: str = ""
    action_type: str = ""
    vendor: str = ""
    target: str = ""
    status: str = "pending"
    result: dict[str, Any] = Field(default_factory=dict)
    started_at: str = ""
    completed_at: str = ""
    error: str | None = None


class ReasoningStep(BaseModel):
    """Audit trail entry for the SOC Brain workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SOCBrainState(BaseModel):
    """Full state for a SOC Brain workflow run through the LangGraph workflow."""

    # Input
    trigger_type: TriggerType = TriggerType.ALERT
    trigger_data: dict[str, Any] = Field(default_factory=dict)
    vendor_sources: list[str] = Field(default_factory=list)

    # Ingestion
    normalized_events: list[NormalizedEvent] = Field(default_factory=list)
    vendor_detections: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    enrichment_data: dict[str, Any] = Field(default_factory=dict)

    # Correlation
    correlated_findings: list[CorrelatedFinding] = Field(default_factory=list)
    situations_created: list[Situation] = Field(default_factory=list)
    kill_chain_mapping: dict[str, list[str]] = Field(default_factory=dict)

    # Response
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    executed_actions: list[ExecutedAction] = Field(default_factory=list)
    escalations: list[dict[str, Any]] = Field(default_factory=list)

    # Workflow tracking
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str | None = None

    # Metrics
    mttd_ms: int = 0
    mtta_ms: int = 0
    mttr_ms: int = 0
