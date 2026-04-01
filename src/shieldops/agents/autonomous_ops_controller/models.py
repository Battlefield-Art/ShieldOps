"""State models for the Autonomous Ops Controller Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AOCStage(StrEnum):
    """Stages of the autonomous operations lifecycle."""

    ASSESS_FLEET = "assess_fleet"
    PLAN_OPERATIONS = "plan_operations"
    DISPATCH_TASKS = "dispatch_tasks"
    MONITOR_EXECUTION = "monitor_execution"
    EVALUATE_OUTCOMES = "evaluate_outcomes"
    REPORT = "report"


class OperationType(StrEnum):
    """Types of autonomous operations dispatched to the fleet."""

    THREAT_HUNT = "threat_hunt"
    VULNERABILITY_SCAN = "vulnerability_scan"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_CHECK = "compliance_check"
    PATCH_DEPLOYMENT = "patch_deployment"
    CONFIG_VALIDATION = "config_validation"
    INTELLIGENCE_COLLECTION = "intelligence_collection"
    REMEDIATION = "remediation"


class FleetStatus(StrEnum):
    """Health status of the agent fleet."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    MAINTENANCE = "maintenance"
    OFFLINE = "offline"


class FleetAssessment(BaseModel):
    """Assessment of the agent fleet's current state."""

    assessment_id: str = ""
    total_agents: int = 0
    healthy_count: int = 0
    degraded_count: int = 0
    offline_count: int = 0
    fleet_status: FleetStatus = FleetStatus.HEALTHY
    capacity_utilization: float = Field(default=0.0, ge=0.0, le=1.0)
    available_capacity: float = Field(default=0.0, ge=0.0, le=1.0)
    agent_statuses: list[dict[str, Any]] = Field(default_factory=list)
    assessed_at: datetime | None = None


class OperationPlan(BaseModel):
    """A planned operation for the agent fleet."""

    plan_id: str = ""
    operation_type: OperationType = OperationType.THREAT_HUNT
    priority: str = "medium"
    target_agents: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    estimated_duration_ms: int = 0
    dependencies: list[str] = Field(default_factory=list)
    description: str = ""


class TaskDispatch(BaseModel):
    """A dispatched task to a specific agent."""

    task_id: str = ""
    plan_id: str = ""
    agent_id: str = ""
    operation_type: OperationType = OperationType.THREAT_HUNT
    parameters: dict[str, Any] = Field(default_factory=dict)
    dispatched_at: datetime | None = None
    status: str = "pending"
    timeout_ms: int = 300000


class ExecutionStatus(BaseModel):
    """Execution status of a dispatched task."""

    task_id: str = ""
    agent_id: str = ""
    status: str = "running"
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0
    result_summary: str = ""
    errors: list[str] = Field(default_factory=list)


class OutcomeEvaluation(BaseModel):
    """Evaluation of operation outcomes."""

    evaluation_id: str = ""
    plan_id: str = ""
    tasks_total: int = 0
    tasks_succeeded: int = 0
    tasks_failed: int = 0
    success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_duration_ms: int = 0
    key_findings: list[str] = Field(default_factory=list)
    improvement_suggestions: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutonomousOpsControllerState(BaseModel):
    """Full LangGraph state for the Autonomous Ops Controller agent."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: AOCStage = AOCStage.ASSESS_FLEET
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    fleet_assessment: list[dict[str, Any]] = Field(default_factory=list)
    operation_plans: list[dict[str, Any]] = Field(default_factory=list)
    dispatched_tasks: list[dict[str, Any]] = Field(default_factory=list)
    execution_statuses: list[dict[str, Any]] = Field(default_factory=list)
    outcome_evaluations: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    fleet_health: str = "unknown"
    tasks_dispatched: int = 0
    tasks_succeeded: int = 0
    success_rate: float = 0.0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
