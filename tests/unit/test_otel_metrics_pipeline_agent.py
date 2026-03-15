"""Tests for the OTel Metrics Pipeline Agent."""

from __future__ import annotations

import pytest
import yaml

from shieldops.agents.otel_metrics_pipeline.models import (
    AggregationType,
    CardinalityReport,
    MetricEndpoint,
    MetricPipelineConfig,
    MetricSource,
    MetricStage,
    OTelMetricsPipelineState,
)
from shieldops.agents.otel_metrics_pipeline.nodes import (
    configure_pipeline as configure_pipeline_node,
    discover_endpoints,
    optimize_cardinality,
    validate_coverage,
)
from shieldops.agents.otel_metrics_pipeline.tools import OTelMetricsPipelineToolkit


# ---------------------------------------------------------------------------
# StrEnum tests
# ---------------------------------------------------------------------------


class TestMetricStageEnum:
    def test_values(self) -> None:
        assert MetricStage.DISCOVER == "discover"
        assert MetricStage.CONFIGURE == "configure"
        assert MetricStage.OPTIMIZE == "optimize"
        assert MetricStage.VALIDATE == "validate"

    def test_all_members(self) -> None:
        assert len(MetricStage) == 4


class TestMetricSourceEnum:
    def test_values(self) -> None:
        assert MetricSource.PROMETHEUS == "prometheus"
        assert MetricSource.OTLP == "otlp"
        assert MetricSource.STATSD == "statsd"
        assert MetricSource.HOSTMETRICS == "hostmetrics"
        assert MetricSource.KUBELETSTATS == "kubeletstats"

    def test_all_members(self) -> None:
        assert len(MetricSource) == 5


class TestAggregationTypeEnum:
    def test_values(self) -> None:
        assert AggregationType.SUM == "sum"
        assert AggregationType.LAST_VALUE == "last_value"
        assert AggregationType.HISTOGRAM == "histogram"
        assert AggregationType.EXPONENTIAL_HISTOGRAM == "exponential_histogram"


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestMetricEndpoint:
    def test_defaults(self) -> None:
        ep = MetricEndpoint()
        assert ep.service == ""
        assert ep.source == MetricSource.PROMETHEUS
        assert ep.scrape_interval_s == 15
        assert ep.metric_count == 0

    def test_custom_values(self) -> None:
        ep = MetricEndpoint(
            service="api",
            source=MetricSource.OTLP,
            endpoint="api:4317",
            scrape_interval_s=10,
            metric_count=200,
        )
        assert ep.service == "api"
        assert ep.source == MetricSource.OTLP
        assert ep.metric_count == 200


class TestMetricPipelineConfig:
    def test_defaults(self) -> None:
        cfg = MetricPipelineConfig()
        assert cfg.receivers == []
        assert cfg.processors == []
        assert cfg.exporters == []
        assert cfg.aggregation_temporality == "cumulative"

    def test_custom(self) -> None:
        cfg = MetricPipelineConfig(
            receivers=["prometheus", "otlp"],
            processors=["batch"],
            exporters=["otlp"],
            aggregation_temporality="delta",
        )
        assert len(cfg.receivers) == 2
        assert cfg.aggregation_temporality == "delta"


class TestCardinalityReport:
    def test_defaults(self) -> None:
        rpt = CardinalityReport()
        assert rpt.total_series == 0
        assert rpt.estimated_savings_pct == 0.0

    def test_custom(self) -> None:
        rpt = CardinalityReport(
            service="api",
            total_series=50000,
            high_cardinality_metrics=["http_duration_bucket"],
            recommended_drops=["go_gc_duration"],
            estimated_savings_pct=15.0,
        )
        assert rpt.total_series == 50000
        assert len(rpt.high_cardinality_metrics) == 1


class TestOTelMetricsPipelineState:
    def test_defaults(self) -> None:
        state = OTelMetricsPipelineState()
        assert state.stage == MetricStage.DISCOVER
        assert state.endpoints == []
        assert state.pipeline_config is None
        assert state.golden_signals_coverage == {}
        assert state.error == ""


# ---------------------------------------------------------------------------
# Toolkit tests
# ---------------------------------------------------------------------------


class TestOTelMetricsPipelineToolkit:
    @pytest.fixture()
    def toolkit(self) -> OTelMetricsPipelineToolkit:
        return OTelMetricsPipelineToolkit()

    @pytest.mark.asyncio
    async def test_discover_metric_endpoints(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        endpoints = await toolkit.discover_metric_endpoints("default")
        assert len(endpoints) >= 3
        assert all(isinstance(ep, MetricEndpoint) for ep in endpoints)
        sources = {ep.source for ep in endpoints}
        assert MetricSource.PROMETHEUS in sources

    def test_configure_pipeline_prometheus(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        endpoints = [
            MetricEndpoint(service="svc", source=MetricSource.PROMETHEUS),
        ]
        config = toolkit.configure_pipeline(endpoints)
        assert "prometheus" in config.receivers
        assert "prometheusremotewrite" in config.exporters
        assert config.aggregation_temporality == "cumulative"

    def test_configure_pipeline_statsd_sets_delta(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        endpoints = [
            MetricEndpoint(service="svc", source=MetricSource.STATSD),
        ]
        config = toolkit.configure_pipeline(endpoints)
        assert "statsd" in config.receivers
        assert config.aggregation_temporality == "delta"

    def test_configure_pipeline_multiple_sources(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        endpoints = [
            MetricEndpoint(service="a", source=MetricSource.PROMETHEUS),
            MetricEndpoint(service="b", source=MetricSource.OTLP),
            MetricEndpoint(service="c", source=MetricSource.HOSTMETRICS),
        ]
        config = toolkit.configure_pipeline(endpoints)
        assert "prometheus" in config.receivers
        assert "otlp" in config.receivers
        assert "hostmetrics" in config.receivers
        assert "otlp" in config.exporters

    def test_analyze_cardinality_known_service(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        report = toolkit.analyze_cardinality("api-gateway")
        assert report.service == "api-gateway"
        assert report.total_series > 0
        assert len(report.high_cardinality_metrics) > 0
        assert report.estimated_savings_pct > 0.0

    def test_analyze_cardinality_unknown_service(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        report = toolkit.analyze_cardinality("unknown-svc")
        assert report.service == "unknown-svc"
        assert report.total_series == 5000  # default

    def test_check_golden_signals(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        golden = toolkit.check_golden_signals("default")
        assert set(golden.keys()) == {"latency", "traffic", "errors", "saturation"}
        assert all(golden.values())

    def test_generate_yaml_valid(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        config = MetricPipelineConfig(
            receivers=["prometheus", "otlp"],
            processors=["memory_limiter", "batch", "filter"],
            exporters=["prometheusremotewrite", "otlp"],
        )
        yaml_str = toolkit.generate_metrics_pipeline_yaml(config)
        parsed = yaml.safe_load(yaml_str)
        assert "receivers" in parsed
        assert "processors" in parsed
        assert "exporters" in parsed
        assert "service" in parsed
        assert "metrics" in parsed["service"]["pipelines"]

    def test_generate_yaml_pipeline_references(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        config = MetricPipelineConfig(
            receivers=["prometheus"],
            processors=["batch"],
            exporters=["otlp"],
        )
        yaml_str = toolkit.generate_metrics_pipeline_yaml(config)
        parsed = yaml.safe_load(yaml_str)
        pipeline = parsed["service"]["pipelines"]["metrics"]
        assert pipeline["receivers"] == ["prometheus"]
        assert pipeline["processors"] == ["batch"]
        assert pipeline["exporters"] == ["otlp"]

    def test_generate_yaml_with_endpoints(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        endpoints = [
            MetricEndpoint(
                service="api",
                source=MetricSource.PROMETHEUS,
                endpoint="http://api:9090/metrics",
                scrape_interval_s=30,
            ),
        ]
        config = MetricPipelineConfig(
            receivers=["prometheus"],
            processors=["batch"],
            exporters=["otlp"],
        )
        yaml_str = toolkit.generate_metrics_pipeline_yaml(config, endpoints)
        parsed = yaml.safe_load(yaml_str)
        prom = parsed["receivers"]["prometheus"]
        scrape_cfg = prom["config"]["scrape_configs"][0]
        assert scrape_cfg["scrape_interval"] == "30s"
        assert "api:9090/metrics" in scrape_cfg["static_configs"][0]["targets"]

    def test_generate_yaml_hostmetrics_scrapers(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        config = MetricPipelineConfig(
            receivers=["hostmetrics"],
            processors=["batch"],
            exporters=["otlp"],
        )
        yaml_str = toolkit.generate_metrics_pipeline_yaml(config)
        parsed = yaml.safe_load(yaml_str)
        hm = parsed["receivers"]["hostmetrics"]
        assert "cpu" in hm["scrapers"]
        assert "memory" in hm["scrapers"]

    def test_generate_yaml_statsd_receiver(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        config = MetricPipelineConfig(
            receivers=["statsd"],
            processors=["batch"],
            exporters=["otlp"],
        )
        yaml_str = toolkit.generate_metrics_pipeline_yaml(config)
        parsed = yaml.safe_load(yaml_str)
        assert "statsd" in parsed["receivers"]
        assert parsed["receivers"]["statsd"]["endpoint"] == "0.0.0.0:8125"


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.fixture()
    def toolkit(self) -> OTelMetricsPipelineToolkit:
        return OTelMetricsPipelineToolkit()

    @pytest.mark.asyncio
    async def test_discover_endpoints_node(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        state: dict = {"target_namespace": "prod", "reasoning_chain": []}
        result = await discover_endpoints(state, toolkit)
        assert result["stage"] == "configure"
        assert len(result["endpoints"]) >= 3
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio
    async def test_configure_pipeline_node(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        state: dict = {
            "endpoints": [
                MetricEndpoint(
                    service="svc",
                    source=MetricSource.PROMETHEUS,
                    endpoint="svc:9090",
                ).model_dump(),
            ],
            "reasoning_chain": [],
        }
        result = await configure_pipeline_node(state, toolkit)
        assert result["stage"] == "optimize"
        assert "pipeline_config" in result
        assert "prometheus" in result["pipeline_config"]["receivers"]

    @pytest.mark.asyncio
    async def test_optimize_cardinality_node(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        state: dict = {
            "endpoints": [
                MetricEndpoint(service="api-gateway").model_dump(),
            ],
            "reasoning_chain": [],
        }
        result = await optimize_cardinality(state, toolkit)
        assert result["stage"] == "validate"
        assert len(result["cardinality_reports"]) == 1
        assert result["cardinality_reports"][0]["service"] == "api-gateway"

    @pytest.mark.asyncio
    async def test_validate_coverage_node(
        self, toolkit: OTelMetricsPipelineToolkit
    ) -> None:
        config = MetricPipelineConfig(
            receivers=["prometheus"],
            processors=["batch"],
            exporters=["otlp"],
        )
        state: dict = {
            "target_namespace": "default",
            "pipeline_config": config.model_dump(),
            "endpoints": [],
            "reasoning_chain": [],
        }
        result = await validate_coverage(state, toolkit)
        assert "golden_signals_coverage" in result
        assert all(result["golden_signals_coverage"].values())
        assert len(result["reasoning_chain"]) > 0
