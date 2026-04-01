"""State models for the Fleet Coordination Engine Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ────────────────────────────────────────────────


class FCEStage(StrEnum):
    """Workflow stages for fleet coordination."""

    DISCOVER_AGENTS = "discover_agents"
    ASSESS_HEALTH = "assess_health"
    PLAN_ROUTING = "plan_routing"
    DISPATCH_WORK = "dispatch_work"
    MONITOR_PROGRESS = "monitor_progress"
    REPORT = "report"


class AgentRole(StrEnum):
    """Roles of agents in the fleet."""

    INVESTIGATOR = "investigator"
    RESPONDER = "responder"
    HUNTER = "hunter"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    ORCHESTRATOR = "orchestrator"


class DispatchStrategy(StrEnum):
    """Strategies for dispatching work to agents."""

    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    PRIORITY_BASED = "priority_based"
    CAPABILITY_MATCH = "capability_match"
    AFFINITY_BASED = "affinity_based"
    RANDOM = "random"


# ── Domain Models ───────────────────────────────────────────


class FleetAgent(BaseModel):
    """A discovered agent in the fleet."""

    agent_id: str = ""
    agent_name: str = ""
    agent_role: str = AgentRole.ANALYST
    status: str = "idle"
    capabilities: list[str] = Field(
        default_factory=list,
    )
    current_load: int = 0
    max_load: int = 10
    last_heartbeat: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthAssessment(BaseModel):
    """Health assessment for a fleet agent."""

    agent_id: str = ""
    healthy: bool = True
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    error_rate: float = 0.0
    latency_p99_ms: float = 0.0
    uptime_hours: float = 0.0
    issues: list[str] = Field(default_factory=list)


class RoutingPlan(BaseModel):
    """A routing plan for task distribution."""

    plan_id: str = ""
    strategy: str = DispatchStrategy.LEAST_LOADED
    task_count: int = 0
    agent_assignments: list[dict[str, str]] = Field(
        default_factory=list,
    )
    estimated_completion_ms: int = 0
    load_balance_score: float = 0.0


class DispatchResult(BaseModel):
    """Result of dispatching work to an agent."""

    dispatch_id: str = ""
    agent_id: str = ""
    task_id: str = ""
    status: str = "dispatched"
    dispatched_at: str = ""
    priority: str = "medium"
    estimated_duration_ms: int = 0


class ProgressUpdate(BaseModel):
    """Progress update for a dispatched task."""

    dispatch_id: str = ""
    agent_id: str = ""
    task_id: str = ""
    status: str = "in_progress"
    progress_pct: float = 0.0
    elapsed_ms: int = 0
    result_summary: str = ""


# ── Reasoning Step ──────────────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the FCE workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ── LangGraph State ─────────────────────────────────────────


class FleetCoordinationEngineState(BaseModel):
    """Full state for a fleet coordination workflow."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: str = FCEStage.DISCOVER_AGENTS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline outputs
    agents_discovered: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    health_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    routing_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    dispatch_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    progress_updates: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Aggregates
    total_agents: int = 0
    healthy_agents: int = 0
    tasks_dispatched: int = 0
    tasks_completed: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
