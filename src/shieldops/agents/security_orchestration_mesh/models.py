"""State models for the Security Orchestration Mesh Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SOMStage(StrEnum):
    """Workflow stages for security orchestration mesh."""

    DISCOVER_REGIONS = "discover_regions"
    MAP_CAPABILITIES = "map_capabilities"
    DISTRIBUTE_TASKS = "distribute_tasks"
    COORDINATE = "coordinate"
    AGGREGATE_RESULTS = "aggregate_results"
    REPORT = "report"


class RegionStatus(StrEnum):
    """Operational status for a region."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    PROVISIONING = "provisioning"
    DRAINING = "draining"


class TaskPriority(StrEnum):
    """Priority level for distributed tasks."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BACKGROUND = "background"


# ── Domain Models ─────────────────────────────────────


class RegionInfo(BaseModel):
    """Region discovered in the orchestration mesh."""

    region_id: str = ""
    provider: str = ""
    location: str = ""
    status: RegionStatus = RegionStatus.HEALTHY
    agent_count: int = 0
    latency_ms: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class Capability(BaseModel):
    """Security capability mapped in a region."""

    capability_id: str = ""
    region_id: str = ""
    name: str = ""
    capacity: int = 0
    utilization: float = 0.0
    supported_actions: list[str] = Field(default_factory=list)


class DistributedTask(BaseModel):
    """A task distributed across regions."""

    task_id: str = ""
    region_id: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    action: str = ""
    status: str = "pending"
    result: dict[str, Any] = Field(default_factory=dict)


class CoordinationResult(BaseModel):
    """Result from coordinated execution across regions."""

    coordination_id: str = ""
    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    duration_ms: int = 0
    summary: str = ""


class AggregatedResult(BaseModel):
    """Aggregated results from all regions."""

    total_findings: int = 0
    regions_covered: int = 0
    critical_findings: int = 0
    recommendations: list[str] = Field(default_factory=list)


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestration mesh workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityOrchestrationMeshState(BaseModel):
    """Full state for the Security Orchestration Mesh workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SOMStage = SOMStage.DISCOVER_REGIONS
    config: dict[str, Any] = Field(default_factory=dict)

    regions: list[dict[str, Any]] = Field(default_factory=list)
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    distributed_tasks: list[dict[str, Any]] = Field(default_factory=list)
    coordination_results: list[dict[str, Any]] = Field(default_factory=list)
    aggregated_results: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
