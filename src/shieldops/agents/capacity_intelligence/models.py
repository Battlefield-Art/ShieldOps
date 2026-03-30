"""Capacity Intelligence Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CIStage(StrEnum):
    COLLECT_UTILIZATION = "collect_utilization"
    FORECAST_DEMAND = "forecast_demand"
    IDENTIFY_BOTTLENECKS = "identify_bottlenecks"
    OPTIMIZE_RESOURCES = "optimize_resources"
    PLAN_SCALING = "plan_scaling"
    REPORT = "report"


class ResourceType(StrEnum):
    COMPUTE = "compute"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    GPU = "gpu"
    DATABASE = "database"


class CapacityRisk(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    ADEQUATE = "adequate"
    OPTIMAL = "optimal"
    OVERPROVISIONED = "overprovisioned"


class CapacityIntelligenceState(BaseModel):
    request_id: str = ""
    stage: CIStage = CIStage.COLLECT_UTILIZATION
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
