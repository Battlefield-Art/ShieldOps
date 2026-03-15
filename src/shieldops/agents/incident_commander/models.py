"""State models for the Incident Commander Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CommandStage(StrEnum):
    """Stages of the incident command lifecycle."""

    TRIAGE = "triage"
    INVESTIGATE = "investigate"
    COORDINATE = "coordinate"
    RESOLVE = "resolve"
    REVIEW = "review"


class SeverityLevel(StrEnum):
    """Incident severity levels."""

    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"
    SEV4 = "sev4"


class EscalationStatus(StrEnum):
    """Escalation status for incident response."""

    NONE = "none"
    TEAM_LEAD = "team_lead"
    VP_ENG = "vp_eng"
    CTO = "cto"


class IncidentContext(BaseModel):
    """Context describing the incoming incident."""

    alert_id: str
    service: str
    environment: str = "production"
    severity: SeverityLevel = SeverityLevel.SEV3
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)


class AgentTask(BaseModel):
    """A task dispatched to a sub-agent."""

    task_id: str = ""
    agent_type: str
    task_description: str
    status: str = "pending"
    result: dict[str, Any] = Field(default_factory=dict)


class CommandDecision(BaseModel):
    """A decision made by the incident commander."""

    action: str
    reasoning: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_approval: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class IncidentCommanderState(BaseModel):
    """Full state of an incident commander workflow (LangGraph state)."""

    # Input
    request_id: str = ""
    stage: CommandStage = CommandStage.TRIAGE
    incident_context: IncidentContext | None = None

    # Agent coordination
    agent_tasks: list[AgentTask] = Field(default_factory=list)
    decisions: list[CommandDecision] = Field(default_factory=list)

    # Resolution
    resolution_summary: str = ""
    escalation_status: EscalationStatus = EscalationStatus.NONE

    # Metrics
    confidence_score: float = 0.0
    blast_radius: list[str] = Field(default_factory=list)

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
