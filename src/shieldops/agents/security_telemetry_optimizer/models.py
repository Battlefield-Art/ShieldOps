"""State models for the Security Telemetry Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class STOStage(StrEnum):
    """Stages in the telemetry optimization lifecycle."""

    INVENTORY_SOURCES = "inventory_sources"
    ANALYZE_VOLUME = "analyze_volume"
    DETECT_WASTE = "detect_waste"
    OPTIMIZE_ROUTING = "optimize_routing"
    VALIDATE = "validate"
    REPORT = "report"


class TelemetryType(StrEnum):
    """Type of telemetry data source."""

    LOGS = "logs"
    METRICS = "metrics"
    TRACES = "traces"
    EVENTS = "events"
    ALERTS = "alerts"
    FLOWS = "flows"


class OptimizationAction(StrEnum):
    """Actions available for telemetry optimization."""

    DROP_DUPLICATE = "drop_duplicate"
    REDUCE_CARDINALITY = "reduce_cardinality"
    DOWNSAMPLE = "downsample"
    AGGREGATE = "aggregate"
    REROUTE = "reroute"
    COMPRESS = "compress"


# --- Domain models ---


class TelemetrySource(BaseModel):
    """A telemetry data source in the pipeline."""

    source_id: str = ""
    name: str = ""
    telemetry_type: TelemetryType = TelemetryType.LOGS
    volume_gb_day: float = 0.0
    cost_per_gb: float = 0.0
    retention_days: int = 30
    endpoint: str = ""


class VolumeAnalysis(BaseModel):
    """Volume analysis result for a telemetry source."""

    source_id: str = ""
    telemetry_type: TelemetryType = TelemetryType.LOGS
    daily_volume_gb: float = 0.0
    cardinality: int = 0
    duplicate_ratio: float = 0.0
    noise_ratio: float = 0.0
    cost_monthly: float = 0.0


class WasteDetection(BaseModel):
    """Detected telemetry waste or inefficiency."""

    waste_id: str = ""
    source_id: str = ""
    waste_type: str = ""
    volume_wasted_gb: float = 0.0
    cost_impact: float = 0.0
    recommendation: str = ""
    severity: str = "medium"


class RoutingOptimization(BaseModel):
    """Proposed routing optimization for telemetry data."""

    optimization_id: str = ""
    source_id: str = ""
    action: OptimizationAction = OptimizationAction.DOWNSAMPLE
    savings_gb: float = 0.0
    savings_cost: float = 0.0
    quality_impact: str = "minimal"
    description: str = ""


class QualityValidation(BaseModel):
    """Validation result for telemetry quality post-optimization."""

    validation_id: str = ""
    source_id: str = ""
    passed: bool = True
    quality_score: float = 1.0
    data_loss_percent: float = 0.0
    alert_coverage_maintained: bool = True


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the optimizer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityTelemetryOptimizerState(BaseModel):
    """Full state for a security telemetry optimizer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: STOStage = STOStage.INVENTORY_SOURCES

    # Inputs
    pipeline_name: str = ""
    target_sources: list[str] = Field(default_factory=list)
    budget_limit: float = 0.0
    quality_threshold: float = 0.95

    # Pipeline fields
    sources: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    volume_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    waste_detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    optimizations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_savings_gb: float = 0.0
    total_savings_cost: float = 0.0
    quality_maintained: bool = True
    sources_optimized: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
