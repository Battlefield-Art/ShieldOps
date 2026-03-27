"""Tests for shieldops.agents.otel_metrics_pipeline."""

from __future__ import annotations

from shieldops.agents.otel_metrics_pipeline.models import (
    AggregationType,
    MetricSource,
    MetricStage,
    OTelMetricsPipelineState,
)


class TestEnums:
    def test_metricstage_discover(self):
        assert MetricStage.DISCOVER == "discover"

    def test_metricstage_configure(self):
        assert MetricStage.CONFIGURE == "configure"

    def test_metricstage_optimize(self):
        assert MetricStage.OPTIMIZE == "optimize"

    def test_metricstage_validate(self):
        assert MetricStage.VALIDATE == "validate"

    def test_metricsource_prometheus(self):
        assert MetricSource.PROMETHEUS == "prometheus"

    def test_metricsource_otlp(self):
        assert MetricSource.OTLP == "otlp"

    def test_metricsource_statsd(self):
        assert MetricSource.STATSD == "statsd"

    def test_metricsource_hostmetrics(self):
        assert MetricSource.HOSTMETRICS == "hostmetrics"

    def test_aggregationtype_sum(self):
        assert AggregationType.SUM == "sum"

    def test_aggregationtype_last_value(self):
        assert AggregationType.LAST_VALUE == "last_value"

    def test_aggregationtype_histogram(self):
        assert AggregationType.HISTOGRAM == "histogram"

    def test_aggregationtype_exponential_histogram(self):
        assert AggregationType.EXPONENTIAL_HISTOGRAM == "exponential_histogram"


class TestModels:
    def test_state_defaults(self):
        s = OTelMetricsPipelineState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_metrics_pipeline.graph import (
            create_otel_metrics_pipeline_graph,
        )

        sg = create_otel_metrics_pipeline_graph()
        assert sg.compile() is not None
