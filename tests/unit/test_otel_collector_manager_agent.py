"""Tests for the OTel Collector Manager agent."""

from __future__ import annotations

import pytest
import yaml

from shieldops.agents.otel_collector_manager import create_otel_collector_manager_graph
from shieldops.agents.otel_collector_manager.agent import OTelCollectorManagerRunner
from shieldops.agents.otel_collector_manager.models import (
    CollectorAction,
    CollectorConfig,
    DeploymentMode,
    ExporterConfig,
    OTelCollectorManagerState,
    PipelineConfig,
    PipelineType,
    ProcessorConfig,
    ReasoningStep,
    ReceiverConfig,
)
from shieldops.agents.otel_collector_manager.nodes import (
    assess_requirements,
    deploy_and_verify,
    generate_config,
    monitor_health,
)
from shieldops.agents.otel_collector_manager.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_DEPLOY,
    SYSTEM_GENERATE,
    SYSTEM_MONITOR,
)
from shieldops.agents.otel_collector_manager.tools import OTelCollectorManagerToolkit

# ---------------------------------------------------------------------------
# StrEnum tests
# ---------------------------------------------------------------------------


class TestCollectorAction:
    def test_values(self) -> None:
        assert CollectorAction.DEPLOY == "deploy"
        assert CollectorAction.CONFIGURE == "configure"
        assert CollectorAction.SCALE == "scale"
        assert CollectorAction.HEALTH_CHECK == "health_check"
        assert CollectorAction.ROLLBACK == "rollback"

    def test_all_members(self) -> None:
        assert len(CollectorAction) == 5


class TestPipelineType:
    def test_values(self) -> None:
        assert PipelineType.TRACES == "traces"
        assert PipelineType.METRICS == "metrics"
        assert PipelineType.LOGS == "logs"

    def test_all_members(self) -> None:
        assert len(PipelineType) == 3


class TestDeploymentMode:
    def test_values(self) -> None:
        assert DeploymentMode.AGENT == "agent"
        assert DeploymentMode.GATEWAY == "gateway"
        assert DeploymentMode.SIDECAR == "sidecar"

    def test_all_members(self) -> None:
        assert len(DeploymentMode) == 3


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestReceiverConfig:
    def test_defaults(self) -> None:
        r = ReceiverConfig()
        assert r.name == ""
        assert r.type == ""
        assert r.protocol == ""
        assert r.endpoint == ""
        assert r.extra_config == {}

    def test_populated(self) -> None:
        r = ReceiverConfig(
            name="otlp",
            type="otlp",
            protocol="grpc",
            endpoint="0.0.0.0:4317",
            extra_config={"tls": True},
        )
        assert r.name == "otlp"
        assert r.extra_config["tls"] is True


class TestProcessorConfig:
    def test_defaults(self) -> None:
        p = ProcessorConfig()
        assert p.name == ""
        assert p.config == {}


class TestExporterConfig:
    def test_defaults(self) -> None:
        e = ExporterConfig()
        assert e.headers == {}
        assert e.extra_config == {}


class TestPipelineConfig:
    def test_defaults(self) -> None:
        p = PipelineConfig()
        assert p.type == PipelineType.TRACES
        assert p.receivers == []

    def test_populated(self) -> None:
        p = PipelineConfig(
            name="traces",
            type=PipelineType.TRACES,
            receivers=["otlp"],
            processors=["batch"],
            exporters=["otlp/shieldops"],
        )
        assert p.receivers == ["otlp"]


class TestCollectorConfig:
    def test_defaults(self) -> None:
        c = CollectorConfig()
        assert c.deployment_mode == DeploymentMode.AGENT
        assert c.receivers == []
        assert c.extensions == []


class TestOTelCollectorManagerState:
    def test_defaults(self) -> None:
        s = OTelCollectorManagerState()
        assert s.action == CollectorAction.DEPLOY
        assert s.target_namespace == "default"
        assert s.error == ""
        assert s.reasoning_chain == []
        assert s.collector_config is None


class TestReasoningStep:
    def test_defaults(self) -> None:
        r = ReasoningStep()
        assert r.step == ""
        assert r.confidence == 0.0


# ---------------------------------------------------------------------------
# Toolkit / YAML generation tests
# ---------------------------------------------------------------------------


def _make_config() -> CollectorConfig:
    return CollectorConfig(
        receivers=[
            ReceiverConfig(name="otlp", type="otlp", protocol="grpc", endpoint="0.0.0.0:4317"),
        ],
        processors=[
            ProcessorConfig(
                name="memory_limiter",
                type="memory_limiter",
                config={"check_interval": "1s", "limit_mib": 512},
            ),
            ProcessorConfig(
                name="batch",
                type="batch",
                config={"timeout": "5s", "send_batch_size": 1024},
            ),
        ],
        exporters=[
            ExporterConfig(
                name="otlp/shieldops",
                type="otlp",
                endpoint="https://otel.shieldops.io:4317",
                headers={"Authorization": "Bearer token"},
            ),
        ],
        pipelines=[
            PipelineConfig(
                name="traces",
                type=PipelineType.TRACES,
                receivers=["otlp"],
                processors=["memory_limiter", "batch"],
                exporters=["otlp/shieldops"],
            ),
        ],
        extensions=["zpages"],
        deployment_mode=DeploymentMode.GATEWAY,
    )


class TestGenerateCollectorYaml:
    def test_produces_valid_yaml(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        config = _make_config()
        raw = toolkit.generate_collector_yaml(config)
        parsed = yaml.safe_load(raw)
        assert isinstance(parsed, dict)

    def test_has_top_level_keys(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        assert "receivers" in parsed
        assert "processors" in parsed
        assert "exporters" in parsed
        assert "service" in parsed

    def test_service_has_pipelines(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        assert "pipelines" in parsed["service"]
        assert "traces" in parsed["service"]["pipelines"]

    def test_pipeline_references(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        traces = parsed["service"]["pipelines"]["traces"]
        assert "otlp" in traces["receivers"]
        assert "memory_limiter" in traces["processors"]
        assert "batch" in traces["processors"]
        assert "otlp/shieldops" in traces["exporters"]

    def test_receiver_endpoint(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        otlp_receiver = parsed["receivers"]["otlp"]
        assert otlp_receiver["protocols"]["grpc"]["endpoint"] == "0.0.0.0:4317"

    def test_exporter_headers(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        exporter = parsed["exporters"]["otlp/shieldops"]
        assert "headers" in exporter
        assert exporter["headers"]["Authorization"] == "Bearer token"

    def test_extensions_in_service(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        assert "extensions" in parsed["service"]
        assert "zpages" in parsed["service"]["extensions"]

    def test_processor_config_values(self) -> None:
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(_make_config()))
        assert parsed["processors"]["memory_limiter"]["check_interval"] == "1s"
        assert parsed["processors"]["batch"]["timeout"] == "5s"

    def test_multiple_pipelines(self) -> None:
        config = _make_config()
        config.pipelines.append(
            PipelineConfig(
                name="metrics",
                type=PipelineType.METRICS,
                receivers=["otlp"],
                processors=["batch"],
                exporters=["otlp/shieldops"],
            )
        )
        toolkit = OTelCollectorManagerToolkit()
        parsed = yaml.safe_load(toolkit.generate_collector_yaml(config))
        assert "traces" in parsed["service"]["pipelines"]
        assert "metrics" in parsed["service"]["pipelines"]


# ---------------------------------------------------------------------------
# Toolkit async method tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deploy_collector_simulated() -> None:
    toolkit = OTelCollectorManagerToolkit()
    result = await toolkit.deploy_collector("default", "config: {}", DeploymentMode.AGENT)
    assert result["status"] == "simulated"
    assert result["workload_type"] == "DaemonSet"


@pytest.mark.asyncio
async def test_deploy_collector_gateway_mode() -> None:
    toolkit = OTelCollectorManagerToolkit()
    result = await toolkit.deploy_collector("prod", "config: {}", DeploymentMode.GATEWAY)
    assert result["workload_type"] == "Deployment"


@pytest.mark.asyncio
async def test_deploy_collector_sidecar_mode() -> None:
    toolkit = OTelCollectorManagerToolkit()
    result = await toolkit.deploy_collector("prod", "config: {}", DeploymentMode.SIDECAR)
    assert result["workload_type"] == "MutatingWebhookConfiguration"


@pytest.mark.asyncio
async def test_check_collector_health_simulated() -> None:
    toolkit = OTelCollectorManagerToolkit()
    result = await toolkit.check_collector_health("default")
    assert result["healthy"] is True
    assert result["total_pods"] == 1


@pytest.mark.asyncio
async def test_scale_collectors_simulated() -> None:
    toolkit = OTelCollectorManagerToolkit()
    result = await toolkit.scale_collectors("default", 5)
    assert result["status"] == "simulated"
    assert result["replicas"] == 5


@pytest.mark.asyncio
async def test_rollback_collector_simulated() -> None:
    toolkit = OTelCollectorManagerToolkit()
    result = await toolkit.rollback_collector("default", revision=2)
    assert result["status"] == "simulated"
    assert result["revision"] == 2


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_requirements_node() -> None:
    toolkit = OTelCollectorManagerToolkit()
    state: dict = {"target_namespace": "monitoring", "action": "deploy", "reasoning_chain": []}
    result = await assess_requirements(state, toolkit)
    assert "health_status" in result
    assert result["health_status"]["healthy"] is True
    assert len(result["reasoning_chain"]) >= 3


@pytest.mark.asyncio
async def test_generate_config_node() -> None:
    toolkit = OTelCollectorManagerToolkit()
    state: dict = {"action": "deploy", "reasoning_chain": []}
    result = await generate_config(state, toolkit)
    assert "collector_config" in result
    config = result["collector_config"]
    assert len(config["receivers"]) >= 2
    assert len(config["processors"]) >= 3
    assert len(config["pipelines"]) == 3


@pytest.mark.asyncio
async def test_deploy_and_verify_node() -> None:
    toolkit = OTelCollectorManagerToolkit()
    config = _make_config()
    state: dict = {
        "target_namespace": "default",
        "action": "deploy",
        "collector_config": config.model_dump(),
        "reasoning_chain": [],
    }
    result = await deploy_and_verify(state, toolkit)
    assert "deployment_result" in result
    assert result["deployment_result"]["status"] == "simulated"
    assert result["health_status"]["healthy"] is True


@pytest.mark.asyncio
async def test_deploy_and_verify_rollback() -> None:
    toolkit = OTelCollectorManagerToolkit()
    state: dict = {
        "target_namespace": "default",
        "action": "rollback",
        "collector_config": _make_config().model_dump(),
        "reasoning_chain": [],
    }
    result = await deploy_and_verify(state, toolkit)
    assert result["deployment_result"]["status"] == "simulated"
    assert result["deployment_result"]["revision"] == 1


@pytest.mark.asyncio
async def test_deploy_and_verify_scale() -> None:
    toolkit = OTelCollectorManagerToolkit()
    state: dict = {
        "target_namespace": "default",
        "action": "scale",
        "collector_config": _make_config().model_dump(),
        "reasoning_chain": [],
    }
    result = await deploy_and_verify(state, toolkit)
    assert result["deployment_result"]["replicas"] == 3


@pytest.mark.asyncio
async def test_monitor_health_node() -> None:
    toolkit = OTelCollectorManagerToolkit()
    state: dict = {"target_namespace": "default", "reasoning_chain": []}
    result = await monitor_health(state, toolkit)
    assert result["health_status"]["healthy"] is True
    assert any("healthy" in r.lower() for r in result["reasoning_chain"])


# ---------------------------------------------------------------------------
# Graph / Runner tests
# ---------------------------------------------------------------------------


class TestCreateGraph:
    def test_creates_graph(self) -> None:
        graph = create_otel_collector_manager_graph()
        assert graph is not None

    def test_graph_has_nodes(self) -> None:
        graph = create_otel_collector_manager_graph()
        assert "assess" in graph.nodes
        assert "generate" in graph.nodes
        assert "deploy" in graph.nodes
        assert "monitor" in graph.nodes


class TestRunner:
    def test_runner_init(self) -> None:
        runner = OTelCollectorManagerRunner()
        assert runner._app is not None


# ---------------------------------------------------------------------------
# Prompt tests
# ---------------------------------------------------------------------------


class TestPrompts:
    def test_prompts_not_empty(self) -> None:
        assert len(SYSTEM_ASSESS) > 50
        assert len(SYSTEM_GENERATE) > 50
        assert len(SYSTEM_DEPLOY) > 50
        assert len(SYSTEM_MONITOR) > 50

    def test_prompts_mention_otel(self) -> None:
        for prompt in [SYSTEM_ASSESS, SYSTEM_GENERATE, SYSTEM_DEPLOY, SYSTEM_MONITOR]:
            assert "otel" in prompt.lower() or "opentelemetry" in prompt.lower()
