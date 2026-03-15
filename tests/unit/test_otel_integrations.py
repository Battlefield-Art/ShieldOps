"""Tests for OpenTelemetry integration tools."""

from __future__ import annotations

import pytest

from shieldops.integrations.otel.collector_manager import (
    CollectorInstance,
    CollectorManager,
    CollectorSpec,
    CollectorStatus,
    DeploymentMode,
)
from shieldops.integrations.otel.kafka_receiver import (
    KafkaOTelReceiver,
    ReceivedTelemetry,
    ReceiverConfig,
)
from shieldops.integrations.otel.pipeline_processor import (
    BatchConfig,
    MemoryLimiterConfig,
    ProcessorChain,
)
from shieldops.integrations.otel.python_instrumentor import (
    SUPPORTED_LIBRARIES,
    InstrumentationConfig,
    InstrumentationMode,
    InstrumentedLibrary,
    PythonInstrumentor,
)


class TestKafkaReceiver:
    def test_receiver_config_defaults(self) -> None:
        cfg = ReceiverConfig()
        assert "localhost:9092" in cfg.brokers
        assert "otel.traces" in cfg.topics
        assert cfg.encoding == "otlp_proto"
        assert cfg.batch_size == 512

    def test_received_telemetry(self) -> None:
        t = ReceivedTelemetry(signal_type="traces", topic="otel.traces", record_count=10)
        assert t.signal_type == "traces"
        assert t.record_count == 10

    @pytest.mark.asyncio
    async def test_receiver_no_consumer(self) -> None:
        receiver = KafkaOTelReceiver()
        await receiver.start()
        result = await receiver.poll()
        assert result is None

    @pytest.mark.asyncio
    async def test_receiver_stats(self) -> None:
        receiver = KafkaOTelReceiver()
        stats = receiver.get_stats()
        assert stats["total_received"] == 0
        assert stats["running"] is False

    @pytest.mark.asyncio
    async def test_receiver_stop(self) -> None:
        receiver = KafkaOTelReceiver()
        await receiver.stop()
        assert receiver.get_stats()["running"] is False

    def test_infer_signal_type_traces(self) -> None:
        receiver = KafkaOTelReceiver()
        result = receiver._infer_signal_type([{"topic": "otel.traces"}])
        assert result == "traces"

    def test_infer_signal_type_metrics(self) -> None:
        receiver = KafkaOTelReceiver()
        result = receiver._infer_signal_type([{"topic": "otel.metrics"}])
        assert result == "metrics"

    def test_infer_signal_type_unknown(self) -> None:
        receiver = KafkaOTelReceiver()
        result = receiver._infer_signal_type([{"topic": "custom"}])
        assert result == "unknown"


class TestProcessorChain:
    def test_batch_config_defaults(self) -> None:
        cfg = BatchConfig()
        assert cfg.timeout_seconds == 5.0
        assert cfg.send_batch_size == 512

    def test_memory_limiter_defaults(self) -> None:
        cfg = MemoryLimiterConfig()
        assert cfg.limit_mib == 200

    @pytest.mark.asyncio
    async def test_process_empty(self) -> None:
        chain = ProcessorChain()
        result = await chain.process([])
        assert result == []

    @pytest.mark.asyncio
    async def test_process_with_enrichment(self) -> None:
        chain = ProcessorChain(enrichment_attributes={"cluster": "prod-1"})
        records = [{"name": "span1"}, {"name": "span2"}]
        await chain.process(records)
        stats = chain.get_stats()
        assert stats["processed"] == 2
        assert stats["enriched"] == 2

    @pytest.mark.asyncio
    async def test_flush(self) -> None:
        chain = ProcessorChain(batch_config=BatchConfig(send_batch_size=1))
        records = [{"name": "span1"}, {"name": "span2"}]
        result = await chain.process(records)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_resource_detection(self) -> None:
        chain = ProcessorChain()
        records = [{"name": "span1"}]
        await chain.process(records)
        flushed = await chain.flush()
        if flushed:
            assert "resource" in flushed[0]
            assert "host.name" in flushed[0]["resource"]


class TestCollectorManager:
    def test_collector_spec_defaults(self) -> None:
        spec = CollectorSpec()
        assert spec.mode == DeploymentMode.DAEMONSET
        assert spec.replicas == 1
        assert "otlp" in spec.receivers

    def test_collector_instance(self) -> None:
        inst = CollectorInstance(name="test", status=CollectorStatus.RUNNING)
        assert inst.status == CollectorStatus.RUNNING

    @pytest.mark.asyncio
    async def test_deploy_dry_run(self) -> None:
        mgr = CollectorManager()
        spec = CollectorSpec(name="test-collector", mode=DeploymentMode.DAEMONSET)
        result = await mgr.deploy(spec, dry_run=True)
        assert result["status"] == "dry_run"
        assert "config" in result

    @pytest.mark.asyncio
    async def test_deploy_live(self) -> None:
        mgr = CollectorManager()
        spec = CollectorSpec(name="test-collector")
        result = await mgr.deploy(spec, dry_run=False)
        assert result["status"] == "deployed"
        collectors = await mgr.list_collectors()
        assert len(collectors) == 1

    @pytest.mark.asyncio
    async def test_scale_not_found(self) -> None:
        mgr = CollectorManager()
        result = await mgr.scale("missing", 3)
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_health_check(self) -> None:
        mgr = CollectorManager()
        spec = CollectorSpec(name="hc-test")
        await mgr.deploy(spec, dry_run=False)
        result = await mgr.health_check("hc-test")
        assert result["name"] == "hc-test"

    def test_generate_config(self) -> None:
        mgr = CollectorManager()
        spec = CollectorSpec(
            name="gen-test",
            receivers=["otlp", "kafka"],
            exporters=["otlp"],
        )
        config = mgr._generate_config(spec)
        assert config["kind"] == "OpenTelemetryCollector"
        assert "otlp" in config["spec"]["config"]["receivers"]
        assert "kafka" in config["spec"]["config"]["receivers"]


class TestPythonInstrumentor:
    def test_config_defaults(self) -> None:
        cfg = InstrumentationConfig()
        assert cfg.mode == InstrumentationMode.FULL
        assert cfg.trace_sample_rate == 1.0
        assert cfg.max_attributes == 0  # Unlimited

    def test_supported_libraries(self) -> None:
        assert "requests" in SUPPORTED_LIBRARIES
        assert "fastapi" in SUPPORTED_LIBRARIES
        assert "django" in SUPPORTED_LIBRARIES

    def test_detect_libraries(self) -> None:
        instrumentor = PythonInstrumentor()
        libs = instrumentor.detect_libraries()
        assert len(libs) > 0
        assert all(isinstance(lib, InstrumentedLibrary) for lib in libs)

    def test_instrumentation_plan(self) -> None:
        cfg = InstrumentationConfig(
            service_name="test-api",
            mode=InstrumentationMode.FULL,
        )
        instrumentor = PythonInstrumentor(config=cfg)
        plan = instrumentor.get_instrumentation_plan()
        assert plan["service_name"] == "test-api"
        assert plan["mode"] == "full"

    def test_k8s_annotations(self) -> None:
        cfg = InstrumentationConfig(
            service_name="api-server",
            environment="staging",
        )
        instrumentor = PythonInstrumentor(config=cfg)
        annotations = instrumentor.generate_k8s_annotation()
        assert annotations["instrumentation.opentelemetry.io/inject-python"] == "true"
        assert annotations["resource.opentelemetry.io/service.name"] == "api-server"

    def test_env_vars(self) -> None:
        cfg = InstrumentationConfig(
            service_name="api-server",
            exporter_endpoint="http://collector:4317",
            trace_sample_rate=0.5,
        )
        instrumentor = PythonInstrumentor(config=cfg)
        env = instrumentor.generate_env_vars()
        assert env["OTEL_SERVICE_NAME"] == "api-server"
        assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://collector:4317"
        assert env["OTEL_TRACES_SAMPLER_ARG"] == "0.5"

    def test_coverage_report(self) -> None:
        instrumentor = PythonInstrumentor(config=InstrumentationConfig(service_name="test"))
        report = instrumentor.get_coverage_report()
        assert report["service"] == "test"
        assert "coverage_pct" in report
        assert "uninstrumented" in report

    def test_selective_mode(self) -> None:
        cfg = InstrumentationConfig(
            service_name="test",
            mode=InstrumentationMode.SELECTIVE,
            selected_libraries=["requests"],
        )
        instrumentor = PythonInstrumentor(config=cfg)
        plan = instrumentor.get_instrumentation_plan()
        assert plan["mode"] == "selective"

    def test_minimal_mode(self) -> None:
        cfg = InstrumentationConfig(
            service_name="test",
            mode=InstrumentationMode.MINIMAL,
        )
        instrumentor = PythonInstrumentor(config=cfg)
        plan = instrumentor.get_instrumentation_plan()
        assert plan["mode"] == "minimal"
