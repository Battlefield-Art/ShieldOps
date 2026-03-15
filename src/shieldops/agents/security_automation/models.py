"""State models for the Security Automation Agent."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AutomationStage(StrEnum):
    """Stages of the security automation workflow."""

    TRIAGE = "triage"
    SELECT_PLAYBOOK = "select_playbook"
    EXECUTE = "execute"
    VALIDATE = "validate"
    LEARN = "learn"


class ContainmentAction(StrEnum):
    """Available containment actions."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_TOKEN = "revoke_token"
    NONE = "none"


class PlaybookMatch(StrEnum):
    """Quality of playbook match."""

    EXACT = "exact"
    PARTIAL = "partial"
    FALLBACK = "fallback"
    NONE = "none"


class RiskAlert(BaseModel):
    """A risk-based alert with composite scoring (Splunk RBA style)."""

    entity: str
    entity_type: str = Field(description="Type of entity: user, host, ip, service")
    composite_score: float = Field(ge=0.0, description="Composite risk score from RBA")
    risk_level: str = Field(description="Risk level: critical, high, medium, low")
    tactics_seen: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics observed",
    )
    source_observations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw observations contributing to the risk score",
    )


class PlaybookCandidate(BaseModel):
    """A candidate playbook matched to an alert."""

    playbook_id: str
    name: str
    match_type: PlaybookMatch = PlaybookMatch.NONE
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Confidence in playbook match"
    )
    estimated_duration_seconds: int = 0
    actions: list[str] = Field(
        default_factory=list,
        description="Containment actions this playbook will execute",
    )


class ContainmentResult(BaseModel):
    """Result of a containment action execution."""

    action: ContainmentAction
    target: str
    success: bool
    duration_seconds: float = 0.0
    rollback_available: bool = False
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class LearningOutcome(BaseModel):
    """Outcome recorded for the accept/reject learning loop."""

    alert_entity: str
    playbook_id: str
    actions_taken: list[str] = Field(default_factory=list)
    success: bool
    feedback: str = ""
    accepted: bool = True


class SecurityAutomationState(BaseModel):
    """Full state of a security automation workflow (LangGraph state)."""

    # Input
    request_id: str = ""
    stage: AutomationStage = AutomationStage.TRIAGE

    # Alerts
    alerts: list[RiskAlert] = Field(default_factory=list)
    triaged_alerts: list[RiskAlert] = Field(default_factory=list)

    # Playbook selection
    selected_playbook: PlaybookCandidate | None = None

    # Execution
    containment_results: list[ContainmentResult] = Field(default_factory=list)
    dry_run: bool = True

    # Validation
    validation_passed: bool | None = None

    # Learning
    learning_outcome: LearningOutcome | None = None

    # Metadata
    confidence_score: float = 0.0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    autonomous_threshold: float = 0.85
    current_step: str = "init"
    error: str | None = None
