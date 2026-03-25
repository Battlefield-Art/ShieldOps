"""State models for the RunbookAutomation LangGraph workflow."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AutomationStage(StrEnum):
    """Stages of the runbook automation workflow."""

    SELECT_RUNBOOK = "select_runbook"
    VALIDATE_PRECONDITIONS = "validate_preconditions"
    REQUEST_APPROVAL = "request_approval"
    EXECUTE_STEPS = "execute_steps"
    VERIFY_OUTCOME = "verify_outcome"
    REPORT = "report"


class RunbookStatus(StrEnum):
    """Overall runbook execution status."""

    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class StepResult(StrEnum):
    """Result of an individual execution step."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ROLLED_BACK = "rolled_back"


class Runbook(BaseModel):
    """A runbook definition with steps and metadata."""

    id: str = ""
    name: str = ""
    description: str = ""
    trigger: str = ""
    target_service: str = ""
    steps: list[dict[str, Any]] = Field(default_factory=list)
    approval_required: bool = True
    estimated_duration_min: int = 5
    risk_level: str = "medium"
    last_executed: float = 0.0


class PreconditionCheck(BaseModel):
    """Result of a precondition validation check."""

    id: str = ""
    runbook_id: str = ""
    check_name: str = ""
    passed: bool = False
    details: str = ""
    blocking: bool = True


class ApprovalRequest(BaseModel):
    """An approval request for runbook execution."""

    id: str = ""
    runbook_id: str = ""
    requester: str = ""
    approver: str = ""
    status: str = "pending"
    requested_at: float = 0.0
    decided_at: float = 0.0
    reason: str = ""


class ExecutionStep(BaseModel):
    """Result of executing a single runbook step."""

    id: str = ""
    runbook_id: str = ""
    step_number: int = 0
    step_name: str = ""
    command: str = ""
    result: StepResult = StepResult.SKIPPED
    output: str = ""
    duration_ms: float = 0.0
    rollback_command: str = ""


class OutcomeVerification(BaseModel):
    """Result of verifying a runbook execution outcome."""

    id: str = ""
    runbook_id: str = ""
    verification_name: str = ""
    passed: bool = False
    expected: str = ""
    actual: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the runbook_automation workflow."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunbookAutomationState(BaseModel):
    """Full state for a runbook_automation workflow run."""

    request_id: str = ""
    stage: AutomationStage = AutomationStage.SELECT_RUNBOOK
    tenant_id: str = ""
    runbook: Runbook | None = None
    precondition_checks: list[PreconditionCheck] = Field(default_factory=list)
    approval: ApprovalRequest | None = None
    execution_steps: list[ExecutionStep] = Field(default_factory=list)
    outcome_verifications: list[OutcomeVerification] = Field(default_factory=list)
    rollback_triggered: bool = False
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str | None = None
