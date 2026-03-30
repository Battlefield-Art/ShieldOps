"""Predictive Scaler Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PSStage(StrEnum):
    COLLECT_METRICS = "collect_metrics"
    ANALYZE_PATTERNS = "analyze_patterns"
    PREDICT_DEMAND = "predict_demand"
    PLAN_SCALING = "plan_scaling"
    EXECUTE_SCALING = "execute_scaling"
    REPORT = "report"


class ScalingDirection(StrEnum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    NO_CHANGE = "no_change"


class ResourceType(StrEnum):
    COMPUTE = "compute"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    GPU = "gpu"
    CONTAINER = "container"


class MetricSnapshot(BaseModel):
    """A point-in-time resource utilization snapshot."""

    id: str = ""
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.COMPUTE
    region: str = ""
    cpu_pct: float = 0.0
    memory_pct: float = 0.0
    requests_per_sec: float = 0.0
    latency_p99_ms: float = 0.0
    timestamp: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class DemandPattern(BaseModel):
    """A detected demand pattern from historical metrics."""

    id: str = ""
    resource_id: str = ""
    pattern_type: str = ""
    periodicity: str = ""
    peak_hour_utc: int = 0
    avg_utilization: float = 0.0
    peak_utilization: float = 0.0
    trend: str = ""
    confidence: float = 0.0


class DemandPrediction(BaseModel):
    """A forward-looking demand prediction."""

    id: str = ""
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.COMPUTE
    predicted_cpu_pct: float = 0.0
    predicted_memory_pct: float = 0.0
    predicted_rps: float = 0.0
    horizon_minutes: int = 60
    confidence: float = 0.0
    breach_threshold: bool = False
    recommended_direction: ScalingDirection = ScalingDirection.NO_CHANGE


class ScalingPlan(BaseModel):
    """A scaling action plan for a resource."""

    id: str = ""
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.COMPUTE
    direction: ScalingDirection = ScalingDirection.NO_CHANGE
    current_capacity: int = 0
    target_capacity: int = 0
    reason: str = ""
    estimated_cost_delta: float = 0.0
    auto_executable: bool = False
    priority: str = "medium"


class ScalingExecution(BaseModel):
    """Result of executing a scaling plan."""

    id: str = ""
    plan_id: str = ""
    status: str = ""
    previous_capacity: int = 0
    new_capacity: int = 0
    latency_ms: float = 0.0
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PredictiveScalerState(BaseModel):
    """Main state for the Predictive Scaler agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: PSStage = PSStage.COLLECT_METRICS

    metrics: list[MetricSnapshot] = Field(
        default_factory=list,
    )
    patterns: list[DemandPattern] = Field(
        default_factory=list,
    )
    predictions: list[DemandPrediction] = Field(
        default_factory=list,
    )
    scaling_plans: list[ScalingPlan] = Field(
        default_factory=list,
    )
    executions: list[ScalingExecution] = Field(
        default_factory=list,
    )

    report: str = ""
    total_resources_monitored: int = 0
    total_scaling_actions: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
