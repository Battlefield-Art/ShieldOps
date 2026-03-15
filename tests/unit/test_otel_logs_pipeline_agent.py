"""Tests for the OTel Logs Pipeline agent."""

from __future__ import annotations

import pytest
import yaml

from shieldops.agents.otel_logs_pipeline.models import (
    LogEndpoint,
    LogFormat,
    LogParsingResult,
    LogPipelineConfig,
    LogSource,
    LogStage,
    OTelLogsPipelineState,
)
from shieldops.agents.otel_logs_pipeline.tools import OTelLogsPipelineToolkit


class TestLogStageEnum:
    def test_stage_values(self) -> None:
        assert LogStage.DISCOVER == "discover"
        assert LogStage.CONFIGURE == "configure"
        assert LogStage.PARSE == "parse"
        assert LogStage.VALIDATE == "validate"

    def test_stage_count(self) -> None:
        assert len(LogStage) == 4


class TestLogSourceEnum:
    def test_source_values(self) -> None:
        assert LogSource.FILELOG == "filelog"
        assert LogSource.SYSLOG == "syslog"
        assert LogSource.OTLP == "otlp"
        assert LogSource.KAFKA == "kafka"
        assert LogSource.JOURNALD == "journald"
        assert LogSource.WINDOWSEVENTLOG == "windowseventlog"

    def test_source_count(self) -> None:
        assert len(LogSource) == 6


class TestLogFormatEnum:
    def test_format_values(self) -> None:
        assert LogFormat.JSON == "json"
        assert LogFormat.TEXT == "text"
        assert LogFormat.REGEX == "regex"
        assert LogFormat.CSV == "csv"
        assert LogFormat.SYSLOG_RFC5424 == "syslog_rfc5424"

    def test_format_count(self) -> None:
        assert len(LogFormat) == 5


class TestLogEndpointModel:
    def test_defaults(self) -> None:
        ep = LogEndpoint()
        assert ep.service == ""
        assert ep.source == LogSource.FILELOG
        assert ep.path_or_endpoint == ""
        assert ep.format == LogFormat.JSON
        assert ep.volume_per_min == 0
        assert ep.parse_rules == []

    def test_full_creation(self) -> None:
        ep = LogEndpoint(
            service="api-gateway",
            source=LogSource.SYSLOG,
            path_or_endpoint="0.0.0.0:514",
            format=LogFormat.SYSLOG_RFC5424,
            volume_per_min=800,
            parse_rules=["syslog_parser"],
        )
        assert ep.service == "api-gateway"
        assert ep.source == LogSource.SYSLOG
        assert ep.volume_per_min == 800
        assert len(ep.parse_rules) == 1


class TestLogPipelineConfigModel:
    def test_defaults(self) -> None:
        cfg = LogPipelineConfig()
        assert cfg.receivers == []
        assert cfg.processors == []
        assert cfg.exporters == []
        assert cfg.resource_attributes == {}

    def test_with_values(self) -> None:
        cfg = LogPipelineConfig(
            receivers=["filelog", "otlp"],
            processors=["batch"],
            exporters=["otlp", "loki"],
            resource_attributes={"cluster": "prod"},
        )
        assert len(cfg.receivers) == 2
        assert cfg.resource_attributes["cluster"] == "prod"


class TestLogParsingResultModel:
    def test_defaults(self) -> None:
        r = LogParsingResult()
        assert r.service == ""
        assert r.parsed_pct == 0.0
        assert r.failed_pct == 0.0
        assert r.sample_errors == []

    def test_with_errors(self) -> None:
        r = LogParsingResult(
            service="auth",
            parsed_pct=95.0,
            failed_pct=5.0,
            sample_errors=["bad line"],
        )
        assert r.parsed_pct + r.failed_pct == 100.0
        assert len(r.sample_errors) == 1


class TestOTelLogsPipelineState:
    def test_defaults(self) -> None:
        state = OTelLogsPipelineState()
        assert state.request_id == ""
        assert state.stage == LogStage.DISCOVER
        assert state.endpoints == []
        assert state.pipeline_config is None
        assert state.parsing_results == []
        assert state.trace_correlation_rate == 0.0
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_with_data(self) -> None:
        ep = LogEndpoint(service="svc1", volume_per_min=100)
        state = OTelLogsPipelineState(
            request_id="req-1",
            stage=LogStage.PARSE,
            endpoints=[ep],
            trace_correlation_rate=0.85,
        )
        assert state.stage == LogStage.PARSE
        assert len(state.endpoints) == 1
        assert state.trace_correlation_rate == 0.85


class TestOTelLogsPipelineToolkit:
    @pytest.mark.asyncio
    async def test_discover_log_sources_no_client(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        sources = await toolkit.discover_log_sources("default")
        assert len(sources) == 5
        assert all(isinstance(s, LogEndpoint) for s in sources)

    @pytest.mark.asyncio
    async def test_discover_log_sources_types(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        sources = await toolkit.discover_log_sources("default")
        source_types = {s.source for s in sources}
        assert LogSource.FILELOG in source_types
        assert LogSource.SYSLOG in source_types
        assert LogSource.OTLP in source_types
        assert LogSource.KAFKA in source_types
        assert LogSource.JOURNALD in source_types

    @pytest.mark.asyncio
    async def test_discover_returns_volumes(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        sources = await toolkit.discover_log_sources("default")
        for s in sources:
            assert s.volume_per_min > 0

    def test_configure_log_pipeline_receivers(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        endpoints = [
            LogEndpoint(service="a", source=LogSource.FILELOG),
            LogEndpoint(service="b", source=LogSource.OTLP),
            LogEndpoint(service="c", source=LogSource.KAFKA),
        ]
        config = toolkit.configure_log_pipeline(endpoints)
        assert "filelog" in config.receivers
        assert "otlp" in config.receivers
        assert "kafka" in config.receivers
        assert "syslog" not in config.receivers

    def test_configure_log_pipeline_processors(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        endpoints = [LogEndpoint(service="a", source=LogSource.FILELOG)]
        config = toolkit.configure_log_pipeline(endpoints)
        assert "memory_limiter" in config.processors
        assert "batch" in config.processors
        assert "attributes" in config.processors
        assert "resource" in config.processors
        assert "transform" in config.processors
        assert "filter" in config.processors

    def test_configure_log_pipeline_exporters(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        endpoints = [
            LogEndpoint(service="a", source=LogSource.SYSLOG),
            LogEndpoint(service="b", source=LogSource.FILELOG),
        ]
        config = toolkit.configure_log_pipeline(endpoints)
        assert "otlp" in config.exporters
        assert "loki" in config.exporters
        assert "elasticsearch" in config.exporters

    def test_configure_log_pipeline_resource_attributes(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        endpoints = [LogEndpoint(service="a")]
        config = toolkit.configure_log_pipeline(endpoints)
        assert "cluster" in config.resource_attributes
        assert "environment" in config.resource_attributes

    def test_test_log_parsing_known_service(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        result = toolkit.test_log_parsing("api-gateway")
        assert result.service == "api-gateway"
        assert result.parsed_pct == 98.5
        assert result.failed_pct == 1.5
        assert len(result.sample_errors) == 1

    def test_test_log_parsing_unknown_service(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        result = toolkit.test_log_parsing("unknown-svc")
        assert result.service == "unknown-svc"
        assert result.parsed_pct == 90.0
        assert result.failed_pct == 10.0

    def test_check_trace_correlation(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        result = toolkit.check_trace_correlation("default")
        assert result["namespace"] == "default"
        assert result["overall_correlation_rate"] == 0.82
        assert "services" in result
        assert "api-gateway" in result["services"]

    def test_check_trace_correlation_node_agent_no_trace(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        result = toolkit.check_trace_correlation("default")
        node_agent = result["services"]["node-agent"]
        assert node_agent["correlation_rate"] == 0.0
        assert node_agent["has_trace_id"] is False

    def test_generate_logs_pipeline_yaml_valid(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        config = LogPipelineConfig(
            receivers=["filelog", "otlp"],
            processors=["memory_limiter", "batch"],
            exporters=["otlp"],
            resource_attributes={"cluster": "test"},
        )
        result = toolkit.generate_logs_pipeline_yaml(config)
        parsed = yaml.safe_load(result)
        assert "receivers" in parsed
        assert "processors" in parsed
        assert "exporters" in parsed
        assert "service" in parsed
        assert "logs" in parsed["service"]["pipelines"]

    def test_generate_yaml_filelog_receiver(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        ep = LogEndpoint(
            service="svc",
            source=LogSource.FILELOG,
            path_or_endpoint="/var/log/app/*.log",
        )
        config = LogPipelineConfig(
            receivers=["filelog"],
            processors=["batch"],
            exporters=["otlp"],
        )
        result = toolkit.generate_logs_pipeline_yaml(config, [ep])
        parsed = yaml.safe_load(result)
        assert "/var/log/app/*.log" in parsed["receivers"]["filelog"]["include"]

    def test_generate_yaml_kafka_receiver(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        config = LogPipelineConfig(
            receivers=["kafka"],
            processors=["batch"],
            exporters=["otlp"],
        )
        result = toolkit.generate_logs_pipeline_yaml(config)
        parsed = yaml.safe_load(result)
        assert "kafka" in parsed["receivers"]
        assert parsed["receivers"]["kafka"]["topic"] == "logs-topic"

    def test_generate_yaml_all_exporters(self) -> None:
        toolkit = OTelLogsPipelineToolkit()
        config = LogPipelineConfig(
            receivers=["otlp"],
            processors=["batch"],
            exporters=["otlp", "loki", "elasticsearch"],
        )
        result = toolkit.generate_logs_pipeline_yaml(config)
        parsed = yaml.safe_load(result)
        assert "otlp" in parsed["exporters"]
        assert "loki" in parsed["exporters"]
        assert "elasticsearch" in parsed["exporters"]


class TestOTelLogsPipelineNodes:
    @pytest.mark.asyncio
    async def test_discover_sources_node(self) -> None:
        from shieldops.agents.otel_logs_pipeline.nodes import discover_sources

        toolkit = OTelLogsPipelineToolkit()
        state: dict = {
            "target_namespace": "prod",
            "reasoning_chain": [],
        }
        result = await discover_sources(state, toolkit)
        assert result["stage"] == "configure"
        assert len(result["endpoints"]) == 5
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio
    async def test_configure_pipeline_node(self) -> None:
        from shieldops.agents.otel_logs_pipeline.nodes import configure_pipeline

        toolkit = OTelLogsPipelineToolkit()
        endpoints = await toolkit.discover_log_sources("default")
        state: dict = {
            "endpoints": [ep.model_dump() for ep in endpoints],
            "reasoning_chain": [],
        }
        result = await configure_pipeline(state, toolkit)
        assert result["stage"] == "parse"
        assert result["pipeline_config"] is not None
        assert len(result["pipeline_config"]["receivers"]) > 0

    @pytest.mark.asyncio
    async def test_test_parsing_node(self) -> None:
        from shieldops.agents.otel_logs_pipeline.nodes import test_parsing

        toolkit = OTelLogsPipelineToolkit()
        endpoints = await toolkit.discover_log_sources("default")
        state: dict = {
            "endpoints": [ep.model_dump() for ep in endpoints],
            "reasoning_chain": [],
        }
        result = await test_parsing(state, toolkit)
        assert result["stage"] == "validate"
        assert len(result["parsing_results"]) == 5

    @pytest.mark.asyncio
    async def test_validate_correlation_node(self) -> None:
        from shieldops.agents.otel_logs_pipeline.nodes import validate_correlation

        toolkit = OTelLogsPipelineToolkit()
        endpoints = await toolkit.discover_log_sources("default")
        config = toolkit.configure_log_pipeline(endpoints)
        state: dict = {
            "target_namespace": "default",
            "endpoints": [ep.model_dump() for ep in endpoints],
            "pipeline_config": config.model_dump(),
            "reasoning_chain": [],
        }
        result = await validate_correlation(state, toolkit)
        assert result["trace_correlation_rate"] == 0.82
        assert len(result["reasoning_chain"]) > 0
