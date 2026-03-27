"""State models for the IntelligentSOAR LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SOARStage(StrEnum):
    """Stages in the intelligent SOAR pipeline."""

    receive_trigger = "receive_trigger"
    select_playbook = "select_playbook"
    execute_steps = "execute_steps"
    adapt_dynamically = "adapt_dynamically"
    validate_outcome = "validate_outcome"
    report = "report"


class PlaybookType(StrEnum):
    """Types of SOAR playbooks."""

    investigation = "investigation"
    containment = "containment"
    eradication = "eradication"
    recovery = "recovery"
    compliance = "compliance"


class ExecutionMode(StrEnum):
    """Execution modes for playbook runs."""

    automatic = "automatic"
    semi_automatic = "semi_automatic"
    manual = "manual"
    dry_run = "dry_run"


class SOARTrigger(BaseModel):
    """Incoming trigger that initiates SOAR workflow."""

    trigger_id: str = ""
    source: str = ""
    alert_type: str = ""
    severity: str = "medium"
    raw_payload: dict[str, Any] = Field(
        default_factory=dict,
    )
    indicators: list[str] = Field(
        default_factory=list,
    )
    timestamp: datetime | None = None


class PlaybookSelection(BaseModel):
    """Result of intelligent playbook selection."""

    playbook_id: str = ""
    playbook_name: str = ""
    playbook_type: str = PlaybookType.investigation
    match_score: float = 0.0
    reasoning: str = ""
    estimated_steps: int = 0
    requires_approval: bool = False


class ExecutionStep(BaseModel):
    """A single step within a playbook execution."""

    step_id: str = ""
    step_name: str = ""
    action_type: str = ""
    target: str = ""
    vendor: str = ""
    status: str = "pending"
    result: dict[str, Any] = Field(
        default_factory=dict,
    )
    duration_ms: int = 0
    was_adapted: bool = False


class AdaptiveDecision(BaseModel):
    """Record of a dynamic mid-execution adaptation."""

    decision_id: str = ""
    trigger_finding: str = ""
    original_step: str = ""
    adapted_step: str = ""
    reasoning: str = ""
    confidence: float = 0.0


class OutcomeValidation(BaseModel):
    """Validation result for playbook outcome."""

    validated: bool = False
    threat_neutralized: bool = False
    residual_risk: float = 1.0
    evidence: list[str] = Field(
        default_factory=list,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )


class SOARReasoningStep(BaseModel):
    """Audit trail entry for the intelligent SOAR workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class IntelligentSOARState(BaseModel):
    """Full state for an intelligent SOAR workflow run."""

    session_id: str = ""
    tenant_id: str = ""
    execution_mode: str = ExecutionMode.automatic
    trigger: SOARTrigger | None = None
    selected_playbook: PlaybookSelection | None = None
    execution_steps: list[ExecutionStep] = Field(
        default_factory=list,
    )
    adaptive_decisions: list[AdaptiveDecision] = Field(
        default_factory=list,
    )
    outcomes: OutcomeValidation | None = None
    playbooks_executed: int = 0
    steps_completed: int = 0
    adaptation_rate: float = 0.0
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[SOARReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
