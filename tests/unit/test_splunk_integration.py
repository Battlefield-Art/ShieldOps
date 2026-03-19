"""Tests for Splunk Observability Cloud integration."""

from __future__ import annotations

import pytest

from shieldops.integrations.splunk.detectors import (
    DetectorDefinition,
    DetectorSeverity,
    SplunkDetectorManager,
)
from shieldops.integrations.splunk.ingest import (
    MetricType,
    SplunkDataPoint,
    SplunkEvent,
    SplunkIngestClient,
    SplunkSpan,
)
from shieldops.integrations.splunk.signalflow import (
    SignalFlowClient,
    SignalFlowProgram,
    SignalFlowResult,
)


# =====================================================================
# Data model tests
# =====================================================================


class TestSplunkDataPoint:
    def test_defaults(self):
        dp = SplunkDataPoint(metric="cpu.usage", value=42.5)
        assert dp.metric == "cpu.usage"
        assert dp.value == 42.5
        assert dp.metric_type == MetricType.GAUGE
        assert dp.dimensions == {}
        assert dp.timestamp > 0

    def test_custom_dimensions(self):
        dp = SplunkDataPoint(
            metric="mem.used",
            value=1024.0,
            metric_type=MetricType.COUNTER,
            dimensions={"host": "web-1"},
        )
        assert dp.metric_type == MetricType.COUNTER
        assert dp.dimensions["host"] == "web-1"

    def test_metric_type_enum(self):
        assert MetricType.GAUGE == "gauge"
        assert MetricType.COUNTER == "counter"
        assert MetricType.CUMULATIVE_COUNTER == "cumulative_counter"


class TestSplunkEvent:
    def test_defaults(self):
        evt = SplunkEvent(eventType="deploy")
        assert evt.eventType == "deploy"
        assert evt.category == "USER_DEFINED"
        assert evt.dimensions == {}
        assert evt.properties == {}
        assert evt.timestamp > 0

    def test_custom_properties(self):
        evt = SplunkEvent(
            eventType="incident",
            properties={"severity": "critical", "agent": "investigation"},
        )
        assert evt.properties["severity"] == "critical"


class TestSplunkSpan:
    def test_defaults(self):
        span = SplunkSpan(traceId="abc123", id="span1", name="investigate")
        assert span.traceId == "abc123"
        assert span.id == "span1"
        assert span.kind == "SERVER"
        assert span.duration == 0
        assert span.parentId == ""
        assert span.tags == {}

    def test_with_tags(self):
        span = SplunkSpan(
            traceId="t1",
            id="s1",
            name="remediate",
            tags={"agent_type": "remediation"},
            duration=5000,
        )
        assert span.tags["agent_type"] == "remediation"
        assert span.duration == 5000


# =====================================================================
# Ingest client tests (buffered / test mode)
# =====================================================================


class TestSplunkIngestClient:
    def test_init_defaults(self):
        client = SplunkIngestClient()
        assert client._realm == "us1"
        assert client._token == ""
        assert client._base_url == "https://ingest.us1.signalfx.com"

    def test_init_custom_realm(self):
        client = SplunkIngestClient(realm="eu0")
        assert client._base_url == "https://ingest.eu0.signalfx.com"

    def test_init_base_url_override(self):
        client = SplunkIngestClient(base_url="http://localhost:9999")
        assert client._base_url == "http://localhost:9999"

    def test_headers(self):
        client = SplunkIngestClient(ingest_token="tok_123")
        headers = client._headers()
        assert headers["X-SF-Token"] == "tok_123"
        assert headers["Content-Type"] == "application/json"

    def test_get_buffered_empty(self):
        client = SplunkIngestClient()
        buf = client.get_buffered()
        assert buf == {"datapoints": [], "traces": [], "events": []}

    @pytest.mark.asyncio
    async def test_send_metrics_buffered(self):
        client = SplunkIngestClient()
        dp = SplunkDataPoint(metric="agent.cpu", value=0.75)
        result = await client.send_metrics([dp])
        assert result["status"] == "buffered"
        assert result["count"] == 1
        assert len(client.get_buffered()["datapoints"]) == 1

    @pytest.mark.asyncio
    async def test_send_traces_buffered(self):
        client = SplunkIngestClient()
        span = SplunkSpan(traceId="t1", id="s1", name="test_span")
        result = await client.send_traces([span])
        assert result["status"] == "buffered"
        assert len(client.get_buffered()["traces"]) == 1

    @pytest.mark.asyncio
    async def test_send_events_buffered(self):
        client = SplunkIngestClient()
        evt = SplunkEvent(eventType="deployment")
        result = await client.send_events([evt])
        assert result["status"] == "buffered"
        assert len(client.get_buffered()["events"]) == 1

    @pytest.mark.asyncio
    async def test_send_agent_metrics(self):
        client = SplunkIngestClient()
        result = await client.send_agent_metrics(
            agent_type="investigation",
            metrics={"cpu": 0.65, "memory_mb": 512.0},
            dimensions={"env": "staging"},
        )
        assert result["status"] == "buffered"
        assert result["count"] == 2
        buffered = client.get_buffered()["datapoints"]
        assert len(buffered) == 2
        metrics_names = {dp["metric"] for dp in buffered}
        assert "agent.cpu" in metrics_names
        assert "agent.memory_mb" in metrics_names
        # Check dimensions include agent_type and custom
        for dp in buffered:
            assert dp["dimensions"]["agent_type"] == "investigation"
            assert dp["dimensions"]["env"] == "staging"
            assert dp["dimensions"]["platform"] == "shieldops"

    @pytest.mark.asyncio
    async def test_send_agent_span(self):
        client = SplunkIngestClient()
        result = await client.send_agent_span(
            agent_type="security",
            node_name="detect_threat",
            trace_id="trace-abc",
            span_id="span-001",
            parent_id="span-000",
            duration_us=15000,
            tags={"severity": "high"},
        )
        assert result["status"] == "buffered"
        spans = client.get_buffered()["traces"]
        assert len(spans) == 1
        span = spans[0]
        assert span["name"] == "security.detect_threat"
        assert span["traceId"] == "trace-abc"
        assert span["parentId"] == "span-000"
        assert span["duration"] == 15000
        assert span["tags"]["agent_type"] == "security"
        assert span["tags"]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_multiple_sends_accumulate(self):
        client = SplunkIngestClient()
        await client.send_metrics([SplunkDataPoint(metric="m1", value=1.0)])
        await client.send_metrics([SplunkDataPoint(metric="m2", value=2.0)])
        assert len(client.get_buffered()["datapoints"]) == 2

    def test_clear_buffer(self):
        client = SplunkIngestClient()
        client._buffer["datapoints"].append({"metric": "test", "value": 1})
        client.clear_buffer()
        assert client.get_buffered() == {"datapoints": [], "traces": [], "events": []}


# =====================================================================
# SignalFlow client tests
# =====================================================================


class TestSignalFlowClient:
    def test_init(self):
        client = SignalFlowClient(realm="eu0")
        assert client._realm == "eu0"
        assert client._base_url == "https://stream.eu0.signalfx.com"

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        client = SignalFlowClient()
        result = await client.execute('data("cpu").publish()', program_name="test")
        assert result.program_name == "test"
        assert result.metadata["mode"] == "dry_run"
        assert result.executed_at_ms > 0

    def test_agent_cpu_program(self):
        client = SignalFlowClient()
        prog = client.agent_cpu_program("investigation")
        assert "agent.cpu.utilization" in prog
        assert "investigation" in prog
        assert ".publish()" in prog

    def test_agent_latency_p95_program(self):
        client = SignalFlowClient()
        prog = client.agent_latency_p95_program()
        assert "agent.duration.seconds" in prog
        assert "percentile(95" in prog

    def test_llm_cost_program(self):
        client = SignalFlowClient()
        prog = client.llm_cost_program()
        assert "llm.cost.dollars" in prog
        assert "model" in prog

    def test_agent_success_rate_program(self):
        client = SignalFlowClient()
        prog = client.agent_success_rate_program("security")
        assert "agent.executions.total" in prog
        assert "agent.executions.success" in prog
        assert "security" in prog

    def test_incident_mttr_program(self):
        client = SignalFlowClient()
        prog = client.incident_mttr_program()
        assert "incident.resolution.seconds" in prog
        assert "severity" in prog

    def test_opa_violation_program(self):
        client = SignalFlowClient()
        prog = client.opa_policy_violation_rate_program()
        assert "opa.policy.violations" in prog

    def test_get_all_programs(self):
        client = SignalFlowClient()
        programs = client.get_all_programs()
        assert len(programs) == 6
        names = {p.name for p in programs}
        assert "agent_cpu" in names
        assert "llm_cost" in names
        assert "incident_mttr" in names
        for p in programs:
            assert isinstance(p, SignalFlowProgram)
            assert p.program  # non-empty
            assert p.description  # non-empty


class TestSignalFlowModels:
    def test_program_model(self):
        prog = SignalFlowProgram(
            name="test", program='data("x").publish()', resolution_ms=5000
        )
        assert prog.resolution_ms == 5000

    def test_result_model(self):
        result = SignalFlowResult(program_name="q1")
        assert result.data_points == []
        assert result.metadata == {}
        assert result.executed_at_ms > 0


# =====================================================================
# Detector tests
# =====================================================================


class TestDetectorDefinition:
    def test_create(self):
        det = DetectorDefinition(
            name="test",
            description="A test detector",
            program='detect(when(data("x") > 1)).publish("t")',
            severity=DetectorSeverity.WARNING,
        )
        assert det.name == "test"
        assert det.severity == DetectorSeverity.WARNING
        assert det.notification_channels == []

    def test_severity_enum(self):
        assert DetectorSeverity.CRITICAL == "Critical"
        assert DetectorSeverity.MAJOR == "Major"
        assert DetectorSeverity.MINOR == "Minor"
        assert DetectorSeverity.WARNING == "Warning"
        assert DetectorSeverity.INFO == "Info"


class TestSplunkDetectorManager:
    def test_get_default_detectors(self):
        mgr = SplunkDetectorManager()
        detectors = mgr.get_default_detectors()
        assert len(detectors) == 6
        for det in detectors:
            assert isinstance(det, DetectorDefinition)
            assert det.name
            assert det.description
            assert det.program
            assert det.severity in list(DetectorSeverity)

    def test_default_detectors_have_programs(self):
        mgr = SplunkDetectorManager()
        for det in mgr.get_default_detectors():
            assert "detect(" in det.program
            assert ".publish(" in det.program

    def test_critical_detectors_have_pagerduty(self):
        mgr = SplunkDetectorManager()
        critical = [
            d
            for d in mgr.get_default_detectors()
            if d.severity == DetectorSeverity.CRITICAL
        ]
        assert len(critical) >= 2
        for det in critical:
            assert any("pagerduty" in ch for ch in det.notification_channels)

    @pytest.mark.asyncio
    async def test_sync_detectors_dry_run(self):
        mgr = SplunkDetectorManager()
        result = await mgr.sync_detectors()
        assert result["status"] == "dry_run"
        assert result["count"] == 6
