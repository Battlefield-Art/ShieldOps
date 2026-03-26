"""Capacity Planner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CapacityStage(StrEnum):
    COLLECT_METRICS = "collect_metrics"
    FORECAST_DEMAND = "forecast_demand"
    IDENTIFY_BOTTLENECKS = "identify_bottlenecks"
    PLAN_SCALING = "plan_scaling"
    RECOMMEND = "recommend"
    REPORT = "report"


class ResourceType(StrEnum):
    COMPUTE = "compute"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"


class CapacityRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HEALTHY = "healthy"


class ResourceMetric(BaseModel):
    """A point-in-time capacity measurement for a single resource."""

    id: str = ""
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.COMPUTE
    current_usage_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    peak_usage_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    trend: str = ""
    days_to_exhaustion: int = Field(default=365)
    service: str = ""


class DemandForecast(BaseModel):
    """A forward-looking usage prediction for a resource."""

    id: str = ""
    resource_id: str = ""
    forecasted_usage_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    forecast_horizon_days: int = Field(default=30)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    seasonal_pattern: str = ""


class Bottleneck(BaseModel):
    """A resource bottleneck that may cause an outage."""

    id: str = ""
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.COMPUTE
    severity: CapacityRisk = CapacityRisk.MEDIUM
    description: str = ""
    impact: str = ""
    mitigation: str = ""


class ScalingPlan(BaseModel):
    """A scaling recommendation for a specific resource."""

    id: str = ""
    resource_id: str = ""
    action: str = ""
    current_capacity: str = ""
    recommended_capacity: str = ""
    estimated_cost_delta: float = 0.0
    auto_scalable: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CapacityPlannerState(BaseModel):
    """Main state for the Capacity Planner agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CapacityStage = CapacityStage.COLLECT_METRICS

    # Collected resource metrics
    metrics: list[ResourceMetric] = Field(default_factory=list)

    # Demand forecasts
    forecasts: list[DemandForecast] = Field(default_factory=list)

    # Identified bottlenecks
    bottlenecks: list[Bottleneck] = Field(default_factory=list)

    # Scaling plans
    scaling_plans: list[ScalingPlan] = Field(default_factory=list)

    # Summary / report
    recommendations: list[str] = Field(default_factory=list)
    report: str = ""

    # Stats
    total_resources: int = 0
    critical_count: int = 0
    estimated_monthly_cost_delta: float = 0.0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
