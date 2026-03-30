"""Cloud Migration Planner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CMPStage(StrEnum):
    DISCOVER_WORKLOADS = "discover_workloads"
    ASSESS_READINESS = "assess_readiness"
    PLAN_MIGRATION = "plan_migration"
    VALIDATE_DEPENDENCIES = "validate_dependencies"
    EXECUTE_MIGRATION = "execute_migration"
    REPORT = "report"


class MigrationStrategy(StrEnum):
    REHOST = "rehost"
    REPLATFORM = "replatform"
    REFACTOR = "refactor"
    REPURCHASE = "repurchase"
    RETIRE = "retire"
    RETAIN = "retain"


class MigrationRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class WorkloadProfile(BaseModel):
    """A workload discovered for migration assessment."""

    id: str = ""
    name: str = ""
    workload_type: str = ""
    source_env: str = ""
    target_env: str = ""
    cpu_cores: int = 0
    memory_gb: float = 0.0
    storage_gb: float = 0.0
    monthly_cost: float = 0.0
    dependencies: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class ReadinessAssessment(BaseModel):
    """Readiness assessment result for a workload."""

    workload_id: str = ""
    workload_name: str = ""
    strategy: MigrationStrategy = MigrationStrategy.REHOST
    risk: MigrationRisk = MigrationRisk.MEDIUM
    readiness_score: float = 0.0
    blockers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class MigrationPlan(BaseModel):
    """A concrete migration plan for a workload."""

    id: str = ""
    workload_id: str = ""
    strategy: MigrationStrategy = MigrationStrategy.REHOST
    target_service: str = ""
    estimated_hours: float = 0.0
    estimated_cost: float = 0.0
    wave: int = 1
    prerequisites: list[str] = Field(default_factory=list)


class DependencyMap(BaseModel):
    """Dependency validation result for a migration plan."""

    plan_id: str = ""
    workload_id: str = ""
    upstream: list[str] = Field(default_factory=list)
    downstream: list[str] = Field(default_factory=list)
    circular: bool = False
    migration_order: int = 0
    blockers: list[str] = Field(default_factory=list)


class MigrationExecution(BaseModel):
    """Execution result for a migration plan."""

    id: str = ""
    plan_id: str = ""
    status: str = ""
    progress_pct: float = 0.0
    duration_hours: float = 0.0
    rollback_available: bool = True
    validation_passed: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudMigrationPlannerState(BaseModel):
    """Main state for the Cloud Migration Planner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CMPStage = CMPStage.DISCOVER_WORKLOADS

    workloads: list[WorkloadProfile] = Field(
        default_factory=list,
    )
    assessments: list[ReadinessAssessment] = Field(
        default_factory=list,
    )
    plans: list[MigrationPlan] = Field(
        default_factory=list,
    )
    dependency_maps: list[DependencyMap] = Field(
        default_factory=list,
    )
    executions: list[MigrationExecution] = Field(
        default_factory=list,
    )

    report: str = ""
    total_workloads: int = 0
    total_estimated_cost: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
