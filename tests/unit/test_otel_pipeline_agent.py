"""Tests for the OTel Pipeline agent."""

from __future__ import annotations

import pytest

from shieldops.agents.otel_pipeline.models import (
    CollectorConfig,
    CollectorMode,
    ExporterTarget,
    InstrumentationTarget,
    OTelPipelineState,
    PipelineComponent,
    PipelineHealthMetric,
    PipelineStage,
)
from shieldops.agents.otel_pipeline.tools import OTelPipelineToolkit


class TestOTelPipelineModels:
    def test_pipeline_stage_values(self) -> None:
        assert PipelineStage.DISCOVER == "discover"
        assert PipelineStage.CONFIGURE == "configure"
        assert PipelineStage.VALIDATE == "validate"
        assert PipelineStage.DEPLOY == "deploy"
        assert PipelineStage.MONITOR == "monitor"

    def test_collector_mode_values(self) -> None:
        assert CollectorMode.DAEMONSET == "daemonset"
        assert CollectorMode.SIDECAR == "sidecar"
        assert CollectorMode.GATEWAY == "gateway"

    def test_exporter_target_values(self) -> None:
        assert ExporterTarget.SHIELDOPS == "shieldops"
        assert ExporterTarget.SPLUNK_HEC == "splunk_hec"
        assert ExporterTarget.OTLP_GRPC == "otlp_grpc"

    def test_pipeline_component_defaults(self) -> None:
        comp = PipelineComponent()
        assert comp.name == ""
        assert comp.component_type == ""
        assert comp.enabled is True

    def test_collector_config_creation(self) -> None:
        cfg = CollectorConfig(
            collector_id="test-collector",
            mode=CollectorMode.DAEMONSET,
        )
        assert cfg.collector_id == "test-collector"
        assert cfg.mode == CollectorMode.DAEMONSET
        assert cfg.receivers == []

    def test_instrumentation_target(self) -> None:
        target = InstrumentationTarget(
            service_name="api-server",
            language="python",
            namespace="prod",
        )
        assert target.service_name == "api-server"
        assert target.auto_instrument is True

    def test_pipeline_health_metric(self) -> None:
        metric = PipelineHealthMetric(
            collector_id="c1",
            dropped_spans=5,
            queue_depth=100,
        )
        assert metric.dropped_spans == 5
        assert metric.healthy is True

    def test_otel_pipeline_state_defaults(self) -> None:
        state = OTelPipelineState()
        assert state.stage == PipelineStage.DISCOVER
        assert state.confidence_score == 0.0


class TestOTelPipelineToolkit:
    @pytest.mark.asyncio
    async def test_discover_services_no_client(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.discover_services("test-cluster")
        assert result == []

    @pytest.mark.asyncio
    async def test_list_kafka_topics_no_client(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.list_kafka_topics()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_collector_health(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.get_collector_health("test-collector")
        assert result["collector_id"] == "test-collector"
        assert result["healthy"] is True

    @pytest.mark.asyncio
    async def test_generate_collector_config_defaults(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.generate_collector_config()
        assert result["mode"] == "daemonset"
        assert "receivers" in result["config"]
        assert "processors" in result["config"]
        assert "exporters" in result["config"]
        assert "otlp" in result["config"]["exporters"]

    @pytest.mark.asyncio
    async def test_generate_collector_config_splunk(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.generate_collector_config(exporters=["otlp", "splunk_hec"])
        assert "splunk_hec" in result["config"]["exporters"]
        assert "otlp" in result["config"]["exporters"]

    @pytest.mark.asyncio
    async def test_validate_pipeline_config_valid(self) -> None:
        toolkit = OTelPipelineToolkit()
        config = await toolkit.generate_collector_config()
        result = await toolkit.validate_pipeline_config(config)
        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_validate_pipeline_config_missing_ref(self) -> None:
        toolkit = OTelPipelineToolkit()
        config = {
            "config": {
                "receivers": {},
                "processors": {},
                "exporters": {},
                "service": {
                    "pipelines": {
                        "traces": {
                            "receivers": ["missing_receiver"],
                            "processors": [],
                            "exporters": [],
                        }
                    }
                },
            },
            "resources": {"cpu": "200m", "memory": "256Mi"},
        }
        result = await toolkit.validate_pipeline_config(config)
        assert result["valid"] is False
        assert any("missing_receiver" in e for e in result["errors"])

    @pytest.mark.asyncio
    async def test_deploy_collector_dry_run(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.deploy_collector({"mode": "daemonset"}, dry_run=True)
        assert result["dry_run"] is True
        assert result["deployed"] is False

    @pytest.mark.asyncio
    async def test_auto_instrument_service(self) -> None:
        toolkit = OTelPipelineToolkit()
        result = await toolkit.auto_instrument_service("api-server")
        assert result["service"] == "api-server"
        assert result["dry_run"] is True
        assert "python" in result["annotation_added"]
