"""State models for the Telemetry Optimizer Agent."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OptimizationStage(StrEnum):
    """Stages of the telemetry optimization workflow."""

    ANALYZE = "analyze"
    IDENTIFY_WASTE = "identify_waste"
    PROPOSE = "propose"
    EXPERIMENT = "experiment"
    APPLY = "apply"


class WasteCategory(StrEnum):
    """Categories of telemetry waste."""

    HIGH_CARDINALITY = "high_cardinality"
    OVER_SAMPLING = "over_sampling"
    DUPLICATE_METRICS = "duplicate_metrics"
    UNUSED_DASHBOARDS = "unused_dashboards"
    STALE_ALERTS = "stale_alerts"


class OptimizationImpact(StrEnum):
    """Impact level of an optimization."""

    HIGH_SAVINGS = "high_savings"
    MODERATE_SAVINGS = "moderate_savings"
    LOW_SAVINGS = "low_savings"
    NO_IMPACT = "no_impact"


class TelemetryWaste(BaseModel):
    """A detected instance of telemetry waste."""

    service_name: str
    waste_category: WasteCategory
    estimated_monthly_cost: float = Field(ge=0.0)
    data_volume_gb: float = Field(ge=0.0)
    description: str


class OptimizationProposal(BaseModel):
    """A proposed optimization to reduce telemetry waste."""

    id: str
    waste_category: WasteCategory
    target_service: str
    action: str
    estimated_savings_pct: float = Field(ge=0.0, le=100.0)
    risk: str = "low"
    reversible: bool = True


class OptimizationExperiment(BaseModel):
    """Result of running an optimization experiment."""

    proposal_id: str
    baseline_cost: float = Field(default=0.0, ge=0.0)
    experiment_cost: float = Field(default=0.0, ge=0.0)
    savings_pct: float = 0.0
    observability_impact: str = "none"
    accepted: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class TelemetryOptimizerState(BaseModel):
    """Full state of a telemetry optimization workflow (LangGraph state)."""

    # Input
    request_id: str
    stage: OptimizationStage = OptimizationStage.ANALYZE
    target_namespace: str = ""

    # Analysis findings
    waste_items: list[TelemetryWaste] = Field(default_factory=list)
    proposals: list[OptimizationProposal] = Field(default_factory=list)
    experiments: list[OptimizationExperiment] = Field(default_factory=list)

    # Outputs
    total_savings_pct: float = 0.0
    budget_seconds: int = 300
    confidence_score: float = 0.0

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
    pipeline_costs: dict[str, Any] = Field(default_factory=dict)
