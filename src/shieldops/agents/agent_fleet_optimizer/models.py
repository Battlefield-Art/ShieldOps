"""State models for Agent Fleet Optimizer."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OptimizerStage(StrEnum):
    """Stages of the fleet optimization workflow."""

    COLLECT_FLEET_STATUS = "collect_fleet_status"
    ANALYZE_HEALTH = "analyze_health"
    OPTIMIZE_SCHEDULES = "optimize_schedules"
    DETECT_ISSUES = "detect_issues"
    RECOMMEND_ACTIONS = "recommend_actions"
    REPORT = "report"


class AgentHealth(StrEnum):
    """Health status of an individual agent."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STUCK = "stuck"
    CRASHED = "crashed"
    IDLE = "idle"


class OptimizationAction(StrEnum):
    """Actions the optimizer can recommend."""

    RESTART = "restart"
    RESCHEDULE = "reschedule"
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    DISABLE = "disable"
    ALERT = "alert"


class FleetStatus(BaseModel):
    """Status snapshot of the agent fleet."""

    id: str = ""
    total_agents: int = 0
    agents_running: int = 0
    agents_idle: int = 0
    agents_errored: int = 0
    avg_cpu_pct: float = 0.0
    avg_memory_pct: float = 0.0
    agent_statuses: list[dict[str, Any]] = Field(default_factory=list)


class HealthAnalysis(BaseModel):
    """Analysis of fleet health patterns."""

    id: str = ""
    healthy_count: int = 0
    degraded_count: int = 0
    stuck_count: int = 0
    crashed_count: int = 0
    idle_count: int = 0
    health_score: float = 0.0
    patterns: list[str] = Field(default_factory=list)


class ScheduleOptimization(BaseModel):
    """Recommended schedule changes."""

    id: str = ""
    agent_name: str = ""
    current_schedule: str = ""
    recommended_schedule: str = ""
    reason: str = ""
    expected_improvement_pct: float = 0.0


class AgentIssue(BaseModel):
    """An issue detected with an agent."""

    id: str = ""
    agent_name: str = ""
    issue_type: str = ""
    severity: str = "medium"
    description: str = ""
    since: float = 0.0
    recommended_action: OptimizationAction = OptimizationAction.ALERT


class OptimizationRecommendation(BaseModel):
    """A fleet optimization recommendation."""

    id: str = ""
    action: OptimizationAction = OptimizationAction.ALERT
    target_agent: str = ""
    reason: str = ""
    priority: str = "medium"
    estimated_impact: str = ""
    auto_executable: bool = False


class AgentFleetOptimizerState(BaseModel):
    """Full state of a fleet optimization run."""

    # Identity
    request_id: str = ""
    stage: OptimizerStage = OptimizerStage.COLLECT_FLEET_STATUS
    tenant_id: str = ""

    # Data
    fleet_status: FleetStatus = Field(default_factory=FleetStatus)
    health_analysis: HealthAnalysis = Field(default_factory=HealthAnalysis)
    optimizations: list[ScheduleOptimization] = Field(default_factory=list)
    issues: list[AgentIssue] = Field(default_factory=list)
    recommendations: list[OptimizationRecommendation] = Field(default_factory=list)

    # Metrics
    agents_healthy: int = 0
    agents_issues: int = 0
    utilization_pct: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
