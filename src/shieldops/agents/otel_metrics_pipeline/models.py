"""OTel Metrics Pipeline Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class MetricStage(StrEnum):
    DISCOVER = "discover"
    CONFIGURE = "configure"
    OPTIMIZE = "optimize"
    VALIDATE = "validate"


class MetricSource(StrEnum):
    PROMETHEUS = "prometheus"
    OTLP = "otlp"
    STATSD = "statsd"
    HOSTMETRICS = "hostmetrics"
    KUBELETSTATS = "kubeletstats"


class AggregationType(StrEnum):
    SUM = "sum"
    LAST_VALUE = "last_value"
    HISTOGRAM = "histogram"
    EXPONENTIAL_HISTOGRAM = "exponential_histogram"


class MetricEndpoint(BaseModel):
    """A discovered metric endpoint in the cluster."""

    service: str = ""
    source: MetricSource = MetricSource.PROMETHEUS
    endpoint: str = ""
    scrape_interval_s: int = 15
    metric_count: int = 0


class MetricPipelineConfig(BaseModel):
    """Configuration for an OTel metrics pipeline."""

    receivers: list[str] = Field(default_factory=list)
    processors: list[str] = Field(default_factory=list)
    exporters: list[str] = Field(default_factory=list)
    aggregation_temporality: str = "cumulative"


class CardinalityReport(BaseModel):
    """Cardinality analysis report for a service's metrics."""

    service: str = ""
    total_series: int = 0
    high_cardinality_metrics: list[str] = Field(default_factory=list)
    recommended_drops: list[str] = Field(default_factory=list)
    estimated_savings_pct: float = 0.0


class OTelMetricsPipelineState(BaseModel):
    """Main state for the OTel Metrics Pipeline agent graph."""

    request_id: str = ""
    stage: MetricStage = MetricStage.DISCOVER
    endpoints: list[MetricEndpoint] = Field(default_factory=list)
    pipeline_config: MetricPipelineConfig | None = None
    cardinality_reports: list[CardinalityReport] = Field(default_factory=list)
    golden_signals_coverage: dict[str, bool] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
