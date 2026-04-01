"""State models for the Automated Response Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class AREStage(StrEnum):
    """Workflow stages for automated response engine."""

    ASSESS_INCIDENT = "assess_incident"
    SELECT_PLAYBOOK = "select_playbook"
    PLAN_REMEDIATION = "plan_remediation"
    EXECUTE_ACTIONS = "execute_actions"
    VALIDATE_RESPONSE = "validate_response"
    REPORT = "report"


class ResponseSeverity(StrEnum):
    """Incident severity classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ResponseAction(StrEnum):
    """Remediation actions the engine can execute."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    REVOKE_CREDENTIALS = "revoke_credentials"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_ACCOUNT = "disable_account"
    ROLLBACK_CHANGE = "rollback_change"
    SCALE_DEFENSES = "scale_defenses"
    NOTIFY_STAKEHOLDERS = "notify_stakeholders"


# -- Domain Models -----------------------------------------------------


class IncidentContext(BaseModel):
    """Assessed incident context."""

    incident_id: str = ""
    source: str = ""
    severity: ResponseSeverity = ResponseSeverity.MEDIUM
    attack_vector: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResponsePlaybook(BaseModel):
    """Selected response playbook."""

    playbook_id: str = ""
    name: str = ""
    category: str = ""
    severity_match: ResponseSeverity = ResponseSeverity.MEDIUM
    steps: list[str] = Field(default_factory=list)
    estimated_duration_ms: int = 0
    requires_approval: bool = False


class RemediationAction(BaseModel):
    """A planned remediation action."""

    action_id: str = ""
    action_type: ResponseAction = ResponseAction.BLOCK_IP
    target: str = ""
    priority: int = 0
    parameters: dict[str, Any] = Field(default_factory=dict)
    rollback_plan: str = ""


class ExecutionResult(BaseModel):
    """Result from executing a remediation action."""

    action_id: str = ""
    action_type: ResponseAction = ResponseAction.BLOCK_IP
    success: bool = False
    duration_ms: int = 0
    output: str = ""
    error: str = ""


class ValidationResult(BaseModel):
    """Result from validating the response."""

    validation_id: str = ""
    checks_passed: int = 0
    checks_failed: int = 0
    threat_neutralized: bool = False
    remaining_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the automated response workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutomatedResponseEngineState(BaseModel):
    """Full state for the Automated Response Engine workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: AREStage = AREStage.ASSESS_INCIDENT
    config: dict[str, Any] = Field(default_factory=dict)

    incident_context: list[dict[str, Any]] = Field(default_factory=list)
    selected_playbooks: list[dict[str, Any]] = Field(default_factory=list)
    remediation_plan: list[dict[str, Any]] = Field(default_factory=list)
    execution_results: list[dict[str, Any]] = Field(default_factory=list)
    validation_results: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
