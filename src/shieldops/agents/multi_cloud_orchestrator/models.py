"""Multi Cloud Orchestrator — state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MCOStage(StrEnum):
    """Stages in the orchestration workflow."""

    DISCOVER_RESOURCES = "discover_resources"
    NORMALIZE_INVENTORY = "normalize_inventory"
    COMPARE_PRICING = "compare_pricing"
    OPTIMIZE_PLACEMENT = "optimize_placement"
    EXECUTE_MIGRATION = "execute_migration"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ORACLE = "oracle"
    IBM = "ibm"
    ON_PREMISE = "on_premise"


class PlacementStrategy(StrEnum):
    """Resource placement strategies."""

    COST_OPTIMIZED = "cost_optimized"
    PERFORMANCE_OPTIMIZED = "performance_optimized"
    COMPLIANCE_DRIVEN = "compliance_driven"
    LATENCY_OPTIMIZED = "latency_optimized"
    REDUNDANCY = "redundancy"
    HYBRID = "hybrid"


class MultiCloudOrchestratorState(BaseModel):
    """Full state for the orchestration graph."""

    request_id: str = ""
    stage: MCOStage = MCOStage.DISCOVER_RESOURCES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
