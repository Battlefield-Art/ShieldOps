"""State models for the WorkflowEngine LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class WorkflowStage(StrEnum):
    """Stages in the workflow engine pipeline."""

    LOAD_WORKFLOW = "load_workflow"
    VALIDATE = "validate"
    EXECUTE_STEPS = "execute_steps"
    CHECK_GATES = "check_gates"
    FINALIZE = "finalize"
    REPORT = "report"


class StepType(StrEnum):
    """Types of steps within a workflow."""

    ACTION = "action"
    APPROVAL_GATE = "approval_gate"
    CONDITION = "condition"
    NOTIFICATION = "notification"
    INTEGRATION = "integration"


class WorkflowStatus(StrEnum):
    """Execution status of a workflow or step."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class WorkflowDefinition(BaseModel):
    """Definition of a security workflow template."""

    id: str = ""
    name: str = ""
    description: str = ""
    trigger: str = ""
    steps: list[dict[str, Any]] = Field(default_factory=list)
    timeout_min: int = 30
    created_by: str = ""


class WorkflowStep(BaseModel):
    """A single step within a workflow execution."""

    id: str = ""
    workflow_id: str = ""
    step_type: StepType = StepType.ACTION
    name: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    status: WorkflowStatus = WorkflowStatus.RUNNING
    output: str = ""
    duration_ms: float = 0.0


class ApprovalGate(BaseModel):
    """An approval gate within a workflow requiring human sign-off."""

    id: str = ""
    workflow_id: str = ""
    step_id: str = ""
    approver: str = ""
    status: str = "pending"
    requested_at: float = 0.0
    decided_at: float = 0.0
    reason: str = ""


class WorkflowResult(BaseModel):
    """Final result of a workflow execution."""

    id: str = ""
    workflow_id: str = ""
    status: WorkflowStatus = WorkflowStatus.COMPLETED
    steps_completed: int = 0
    total_steps: int = 0
    duration_min: float = 0.0
    output: dict[str, Any] = Field(default_factory=dict)


class ReasoningStep(BaseModel):
    """Audit trail entry for the workflow engine."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class WorkflowEngineState(BaseModel):
    """Full state for a workflow engine run through the LangGraph workflow."""

    session_id: str = ""
    tenant_id: str = ""
    workflow_name: str = ""
    trigger_data: dict[str, Any] = Field(default_factory=dict)
    workflow_definition: WorkflowDefinition | None = None
    validation_passed: bool = False
    validation_errors: list[str] = Field(default_factory=list)
    executed_steps: list[WorkflowStep] = Field(default_factory=list)
    pending_gates: list[ApprovalGate] = Field(default_factory=list)
    result: WorkflowResult | None = None
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
