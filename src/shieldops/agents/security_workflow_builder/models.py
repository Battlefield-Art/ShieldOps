"""Security Workflow Builder Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SWBStage(StrEnum):
    DEFINE_TRIGGER = "define_trigger"
    BUILD_WORKFLOW = "build_workflow"
    VALIDATE_LOGIC = "validate_logic"
    TEST_EXECUTION = "test_execution"
    DEPLOY = "deploy"
    REPORT = "report"


class TriggerType(StrEnum):
    ALERT = "alert"
    SCHEDULE = "schedule"
    WEBHOOK = "webhook"
    EVENT = "event"
    MANUAL = "manual"
    THRESHOLD = "threshold"


class ActionType(StrEnum):
    NOTIFY = "notify"
    BLOCK = "block"
    ISOLATE = "isolate"
    ENRICH = "enrich"
    ESCALATE = "escalate"
    REMEDIATE = "remediate"


class TriggerDefinition(BaseModel):
    """A workflow trigger condition."""

    id: str = ""
    name: str = ""
    trigger_type: TriggerType = TriggerType.ALERT
    condition: str = ""
    source: str = ""
    severity_filter: str = "any"
    cooldown_seconds: int = 60


class WorkflowStep(BaseModel):
    """A single step in a security workflow."""

    id: str = ""
    name: str = ""
    action_type: ActionType = ActionType.NOTIFY
    config: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300
    on_failure: str = "continue"
    depends_on: list[str] = Field(default_factory=list)


class WorkflowDefinition(BaseModel):
    """A complete workflow definition."""

    id: str = ""
    name: str = ""
    description: str = ""
    trigger_id: str = ""
    steps: list[WorkflowStep] = Field(default_factory=list)
    enabled: bool = True
    version: int = 1


class ValidationResult(BaseModel):
    """Result of workflow logic validation."""

    id: str = ""
    workflow_id: str = ""
    valid: bool = True
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    complexity_score: float = 0.0


class TestExecution(BaseModel):
    """Result of a workflow test execution."""

    id: str = ""
    workflow_id: str = ""
    status: str = ""
    steps_executed: int = 0
    steps_total: int = 0
    duration_ms: int = 0
    output: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class DeploymentRecord(BaseModel):
    """Record of a workflow deployment."""

    id: str = ""
    workflow_id: str = ""
    environment: str = ""
    status: str = ""
    deployed_at: str = ""
    deployed_by: str = ""
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityWorkflowBuilderState(BaseModel):
    """Main state for the Security Workflow Builder agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SWBStage = SWBStage.DEFINE_TRIGGER

    triggers: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    workflows: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    test_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    deployments: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    workflows_built: int = 0
    tests_passed: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
