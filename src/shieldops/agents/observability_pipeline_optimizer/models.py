"""Observability Pipeline Optimizer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OPOStage(StrEnum):
    AUDIT_PIPELINES = "audit_pipelines"
    ANALYZE_CARDINALITY = "analyze_cardinality"
    OPTIMIZE_SAMPLING = "optimize_sampling"
    REDUCE_COSTS = "reduce_costs"
    VALIDATE_QUALITY = "validate_quality"
    REPORT = "report"


class PipelineType(StrEnum):
    TRACES = "traces"
    METRICS = "metrics"
    LOGS = "logs"
    EVENTS = "events"
    PROFILES = "profiles"


class OptimizationAction(StrEnum):
    DROP_UNUSED = "drop_unused"
    REDUCE_CARDINALITY = "reduce_cardinality"
    TAIL_SAMPLE = "tail_sample"
    AGGREGATE = "aggregate"
    COMPRESS = "compress"
    DOWNSAMPLE = "downsample"


class PipelineAudit(BaseModel):
    """Audit result for an observability pipeline."""

    id: str = ""
    name: str = ""
    pipeline_type: PipelineType = PipelineType.TRACES
    vendor: str = ""
    ingestion_rate_gb_day: float = 0.0
    retention_days: int = 30
    monthly_cost: float = 0.0
    utilization_pct: float = 0.0
    cardinality: int = 0
    tags: dict[str, str] = Field(default_factory=dict)


class CardinalityAnalysis(BaseModel):
    """Cardinality analysis for a pipeline or metric."""

    id: str = ""
    pipeline_id: str = ""
    metric_name: str = ""
    label_count: int = 0
    unique_series: int = 0
    explosion_risk: str = "low"
    recommended_action: OptimizationAction = OptimizationAction.REDUCE_CARDINALITY
    estimated_reduction_pct: float = 0.0


class SamplingConfig(BaseModel):
    """Sampling configuration recommendation."""

    id: str = ""
    pipeline_id: str = ""
    pipeline_type: PipelineType = PipelineType.TRACES
    current_sample_rate: float = 1.0
    recommended_rate: float = 0.1
    strategy: str = "tail_sampling"
    estimated_savings_pct: float = 0.0
    quality_impact: str = "minimal"


class CostReduction(BaseModel):
    """A cost reduction opportunity."""

    id: str = ""
    pipeline_id: str = ""
    action: OptimizationAction = OptimizationAction.DROP_UNUSED
    description: str = ""
    current_monthly_cost: float = 0.0
    projected_monthly_cost: float = 0.0
    monthly_savings: float = 0.0
    auto_applicable: bool = False
    risk: str = "low"


class QualityValidation(BaseModel):
    """Quality validation after optimization."""

    id: str = ""
    pipeline_id: str = ""
    metric: str = ""
    pre_optimization_value: float = 0.0
    post_optimization_value: float = 0.0
    within_threshold: bool = True
    threshold: float = 0.95


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ObservabilityPipelineOptimizerState(BaseModel):
    """Main state for the Observability Pipeline Optimizer."""

    request_id: str = ""
    tenant_id: str = ""
    stage: OPOStage = OPOStage.AUDIT_PIPELINES

    pipeline_audits: list[PipelineAudit] = Field(
        default_factory=list,
    )
    cardinality_analyses: list[CardinalityAnalysis] = Field(
        default_factory=list,
    )
    sampling_configs: list[SamplingConfig] = Field(
        default_factory=list,
    )
    cost_reductions: list[CostReduction] = Field(
        default_factory=list,
    )
    quality_validations: list[QualityValidation] = Field(
        default_factory=list,
    )

    report: str = ""
    total_monthly_cost: float = 0.0
    total_monthly_savings: float = 0.0
    total_cardinality_reduced: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
