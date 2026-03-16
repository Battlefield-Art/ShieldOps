"""OTel Metrics Pipeline Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CardinalityOptimizationResult(BaseModel):
    """Structured output from LLM-assisted cardinality optimization."""

    summary: str = Field(description="Brief summary of cardinality analysis")
    high_impact_metrics: list[str] = Field(description="Metrics with highest cardinality impact")
    drop_recommendations: list[str] = Field(
        description="Metrics recommended for dropping or aggregation"
    )
    estimated_savings_pct: float = Field(description="Estimated overall storage savings percentage")


SYSTEM_DISCOVER = """You are an OpenTelemetry metrics pipeline specialist for ShieldOps.
Discover all metric endpoints in the target namespace:

1. Find Prometheus scrape targets via ServiceMonitor/PodMonitor CRDs and annotations
2. Identify OTLP metric sources pushing to the collector
3. Detect StatsD endpoints from application containers
4. Enumerate hostmetrics and kubeletstats receivers
5. Count the number of unique metric names per endpoint

Produce a MetricEndpoint for each discovered source with its service name, source type,
endpoint URL, scrape interval, and metric count.
"""

SYSTEM_CONFIGURE = """You are configuring an OTel Collector metrics pipeline.
Based on discovered endpoints, build an optimal pipeline configuration:

1. Select receivers matching each source type (prometheus, otlp, statsd, hostmetrics)
2. Add processors: batch, memory_limiter, metricstransform, filter
3. Choose exporters: prometheusremotewrite for Prometheus backends, otlp for OTLP backends
4. Set aggregation temporality (cumulative for Prometheus, delta for StatsD)
5. Ensure the pipeline handles all discovered endpoint types

Produce a MetricPipelineConfig with receivers, processors, exporters, and temporality.
"""

SYSTEM_OPTIMIZE = """You are optimizing metric cardinality for cost and performance.
For each service, analyze cardinality and recommend optimizations:

1. Identify metrics with high label cardinality (>10k unique series)
2. Detect unused or redundant metrics (e.g., default Go runtime metrics rarely queried)
3. Recommend metric drops via the filter processor
4. Suggest label dropping or aggregation to reduce series count
5. Estimate storage and ingestion cost savings as a percentage

Produce a CardinalityReport per service with total series, high-cardinality metrics,
recommended drops, and estimated savings.
"""

SYSTEM_VALIDATE = """You are validating golden signals coverage for the metrics pipeline.
Check that the pipeline captures all four golden signals:

1. Latency — request duration histograms (http_server_duration, rpc_server_duration)
2. Traffic — request rate counters (http_server_request_count, rpc_server_requests)
3. Errors — error rate counters (http_server_errors, 5xx status codes)
4. Saturation — resource utilization (cpu, memory, disk, network, queue depth)

Report which signals are covered and flag any gaps. Recommend additional metrics
or receivers to fill coverage holes.
"""
