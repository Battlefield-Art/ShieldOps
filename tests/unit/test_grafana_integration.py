"""Tests for Grafana LGTM stack integration (Loki + Mimir + Tempo + dashboards)."""

from __future__ import annotations

import pytest

from shieldops.integrations.grafana.dashboards import (
    shieldops_agent_dashboard,
    shieldops_security_dashboard,
    shieldops_sre_dashboard,
)
from shieldops.integrations.grafana.loki import LokiClient, LokiPushRequest, LokiStream
from shieldops.integrations.grafana.mimir import MimirClient, MimirMetric
from shieldops.integrations.grafana.tempo import TempoClient, TempoSpan
from shieldops.integrations.grafana.unified import GrafanaLGTMClient

# ======================================================================
# LokiStream / LokiPushRequest model tests
# ======================================================================


class TestLokiModels:
    def test_loki_stream_creation(self):
        stream = LokiStream(labels={"job": "test"})
        assert stream.labels == {"job": "test"}
        assert stream.entries == []

    def test_loki_stream_with_entries(self):
        stream = LokiStream(
            labels={"app": "shieldops"},
            entries=[("1234567890000000000", "hello world")],
        )
        assert len(stream.entries) == 1
        assert stream.entries[0][1] == "hello world"

    def test_loki_push_request(self):
        req = LokiPushRequest(
            streams=[
                LokiStream(labels={"job": "a"}),
                LokiStream(labels={"job": "b"}),
            ]
        )
        assert len(req.streams) == 2

    def test_loki_push_request_empty(self):
        req = LokiPushRequest()
        assert req.streams == []


# ======================================================================
# LokiClient tests (buffered mode — no credentials)
# ======================================================================


class TestLokiClient:
    def test_init_defaults(self):
        client = LokiClient()
        assert client._url == "http://localhost:3100"
        assert client._tenant_id == "shieldops"
        assert client._buffer == []

    def test_init_custom(self):
        client = LokiClient(
            url="https://loki.example.com/",
            tenant_id="myorg",
            username="user",
            password="pass",
        )
        assert client._url == "https://loki.example.com"
        assert client._tenant_id == "myorg"

    @pytest.mark.asyncio
    async def test_push_logs_buffered(self):
        client = LokiClient()
        stream = LokiStream(
            labels={"app": "test"},
            entries=[("1000000000000000000", "test log line")],
        )
        result = await client.push_logs([stream])
        assert result["status"] == "buffered"
        assert result["count"] == 1
        assert len(client.get_buffered()) == 1

    @pytest.mark.asyncio
    async def test_push_agent_log_buffered(self):
        client = LokiClient()
        result = await client.push_agent_log(
            agent_type="investigation",
            level="info",
            message="Agent started investigation",
            extra_labels={"env": "test"},
            structured_metadata={"request_id": "req-123"},
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()
        assert len(buf) == 1
        payload = buf[0]["payload"]
        assert len(payload["streams"]) == 1
        stream = payload["streams"][0]
        assert stream["stream"]["agent_type"] == "investigation"
        assert stream["stream"]["platform"] == "shieldops"
        assert stream["stream"]["level"] == "info"
        assert stream["stream"]["env"] == "test"
        assert "request_id=req-123" in stream["values"][0][1]

    @pytest.mark.asyncio
    async def test_push_agent_log_no_metadata(self):
        client = LokiClient()
        result = await client.push_agent_log(
            agent_type="remediation",
            level="error",
            message="Remediation failed",
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()
        line = buf[0]["payload"]["streams"][0]["values"][0][1]
        assert line == "Remediation failed"
        assert "|" not in line

    @pytest.mark.asyncio
    async def test_query_buffered(self):
        client = LokiClient()
        result = await client.query('{app="test"}')
        assert result == []

    @pytest.mark.asyncio
    async def test_get_labels_buffered(self):
        client = LokiClient()
        result = await client.get_labels()
        assert result == []

    def test_clear_buffer(self):
        client = LokiClient()
        client._buffer.append({"test": True})
        client.clear_buffer()
        assert client.get_buffered() == []


# ======================================================================
# MimirMetric model tests
# ======================================================================


class TestMimirModels:
    def test_mimir_metric_creation(self):
        m = MimirMetric(name="cpu_usage", value=0.85)
        assert m.name == "cpu_usage"
        assert m.value == 0.85
        assert m.labels == {}
        assert m.timestamp_ms > 0

    def test_mimir_metric_with_labels(self):
        m = MimirMetric(
            name="requests_total",
            value=42.0,
            labels={"method": "GET", "status": "200"},
        )
        assert m.labels["method"] == "GET"
        assert m.value == 42.0


# ======================================================================
# MimirClient tests (buffered mode)
# ======================================================================


class TestMimirClient:
    def test_init_defaults(self):
        client = MimirClient()
        assert client._url == "http://localhost:9009"
        assert client._tenant_id == "shieldops"
        assert client._buffer == []

    def test_init_custom(self):
        client = MimirClient(url="https://mimir.example.com/", tenant_id="org2")
        assert client._url == "https://mimir.example.com"

    @pytest.mark.asyncio
    async def test_push_metrics_buffered(self):
        client = MimirClient()
        metrics = [
            MimirMetric(name="test_gauge", value=1.5, labels={"env": "test"}),
            MimirMetric(name="test_counter", value=10.0),
        ]
        result = await client.push_metrics(metrics)
        assert result["status"] == "buffered"
        assert result["count"] == 2
        buf = client.get_buffered()
        assert len(buf) == 1
        payload = buf[0]["payload"]
        assert len(payload) == 2
        assert payload[0]["labels"]["__name__"] == "test_gauge"

    @pytest.mark.asyncio
    async def test_push_agent_metric_buffered(self):
        client = MimirClient()
        result = await client.push_agent_metric(
            agent_type="security",
            metric_name="duration_ms",
            value=150.0,
            extra_labels={"node": "investigate"},
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()
        payload = buf[0]["payload"]
        assert payload[0]["labels"]["__name__"] == "shieldops_agent_duration_ms"
        assert payload[0]["labels"]["agent_type"] == "security"
        assert payload[0]["labels"]["node"] == "investigate"

    @pytest.mark.asyncio
    async def test_query_buffered(self):
        client = MimirClient()
        result = await client.query("shieldops_agent_duration_ms")
        assert result == []

    def test_clear_buffer(self):
        client = MimirClient()
        client._buffer.append({"test": True})
        client.clear_buffer()
        assert client.get_buffered() == []


# ======================================================================
# TempoSpan model tests
# ======================================================================


class TestTempoModels:
    def test_tempo_span_creation(self):
        span = TempoSpan(
            trace_id="abc123",
            span_id="span1",
            operation_name="investigate",
            service_name="shieldops-investigation",
        )
        assert span.trace_id == "abc123"
        assert span.parent_span_id == ""
        assert span.status == "OK"
        assert span.attributes == {}
        assert span.start_time_us > 0

    def test_tempo_span_full(self):
        span = TempoSpan(
            trace_id="abc",
            span_id="s1",
            parent_span_id="s0",
            operation_name="remediate",
            service_name="shieldops-remediation",
            duration_us=5000,
            status="ERROR",
            attributes={"error.message": "timeout"},
        )
        assert span.duration_us == 5000
        assert span.status == "ERROR"


# ======================================================================
# TempoClient tests (buffered mode)
# ======================================================================


class TestTempoClient:
    def test_init_defaults(self):
        client = TempoClient()
        assert client._url == "http://localhost:3200"
        assert client._tenant_id == "shieldops"
        assert client._buffer == []

    @pytest.mark.asyncio
    async def test_push_spans_buffered(self):
        client = TempoClient()
        spans = [
            TempoSpan(
                trace_id="t1",
                span_id="s1",
                operation_name="investigate",
                service_name="shieldops-investigation",
                duration_us=1000,
            ),
        ]
        result = await client.push_spans(spans)
        assert result["status"] == "buffered"
        assert result["count"] == 1
        buf = client.get_buffered()
        assert len(buf) == 1
        assert buf[0]["traceId"] == "t1"
        assert buf[0]["name"] == "investigate"

    @pytest.mark.asyncio
    async def test_push_spans_with_parent(self):
        client = TempoClient()
        span = TempoSpan(
            trace_id="t2",
            span_id="s2",
            parent_span_id="s1",
            operation_name="child_op",
            service_name="svc",
        )
        await client.push_spans([span])
        buf = client.get_buffered()
        assert buf[0]["parentId"] == "s1"

    @pytest.mark.asyncio
    async def test_push_agent_span_buffered(self):
        client = TempoClient()
        result = await client.push_agent_span(
            agent_type="security",
            node_name="detect",
            trace_id="t3",
            span_id="s3",
            duration_us=2000,
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()
        assert buf[0]["name"] == "security.detect"
        assert buf[0]["localEndpoint"]["serviceName"] == "shieldops-security"
        assert buf[0]["tags"]["agent_type"] == "security"

    @pytest.mark.asyncio
    async def test_get_trace_buffered(self):
        client = TempoClient()
        result = await client.get_trace("nonexistent")
        assert result["status"] == "buffered"

    @pytest.mark.asyncio
    async def test_search_traces_buffered(self):
        client = TempoClient()
        result = await client.search_traces(service_name="shieldops-security")
        assert result == []

    def test_clear_buffer(self):
        client = TempoClient()
        client._buffer.append({"test": True})
        client.clear_buffer()
        assert client.get_buffered() == []


# ======================================================================
# GrafanaLGTMClient tests
# ======================================================================


class TestGrafanaLGTMClient:
    def test_init_creates_sub_clients(self):
        client = GrafanaLGTMClient(
            loki_url="http://loki:3100",
            mimir_url="http://mimir:9009",
            tempo_url="http://tempo:3200",
            tenant_id="myorg",
        )
        assert isinstance(client.loki, LokiClient)
        assert isinstance(client.mimir, MimirClient)
        assert isinstance(client.tempo, TempoClient)
        assert client.loki._url == "http://loki:3100"
        assert client.mimir._url == "http://mimir:9009"
        assert client.tempo._url == "http://tempo:3200"
        assert client.loki._tenant_id == "myorg"

    def test_init_defaults(self):
        client = GrafanaLGTMClient()
        assert client.loki._url == "http://localhost:3100"
        assert client.mimir._url == "http://localhost:9009"
        assert client.tempo._url == "http://localhost:3200"

    @pytest.mark.asyncio
    async def test_record_agent_execution(self):
        client = GrafanaLGTMClient()
        result = await client.record_agent_execution(
            agent_type="investigation",
            request_id="req-001",
            node_name="gather_evidence",
            duration_ms=250.0,
            status="success",
            log_message="Investigation completed",
            trace_id="trace-abc",
            span_id="span-def",
        )
        assert result["trace_id"] == "trace-abc"
        assert result["span_id"] == "span-def"
        assert result["loki"]["status"] == "buffered"
        assert result["mimir"]["status"] == "buffered"
        assert result["tempo"]["status"] == "buffered"

        # Verify Loki got the log
        loki_buf = client.loki.get_buffered()
        assert len(loki_buf) == 1

        # Verify Mimir got the metric
        mimir_buf = client.mimir.get_buffered()
        assert len(mimir_buf) == 1

        # Verify Tempo got the span
        tempo_buf = client.tempo.get_buffered()
        assert len(tempo_buf) == 1
        assert tempo_buf[0]["traceId"] == "trace-abc"

    @pytest.mark.asyncio
    async def test_record_agent_execution_auto_ids(self):
        client = GrafanaLGTMClient()
        result = await client.record_agent_execution(
            agent_type="remediation",
            request_id="req-002",
            node_name="apply_fix",
            duration_ms=500.0,
            status="error",
            log_message="Remediation failed: timeout",
        )
        # trace_id and span_id should be auto-generated
        assert len(result["trace_id"]) > 0
        assert len(result["span_id"]) > 0

    @pytest.mark.asyncio
    async def test_query_agent_logs(self):
        client = GrafanaLGTMClient()
        result = await client.query_agent_logs("investigation")
        assert result == []

    @pytest.mark.asyncio
    async def test_query_agent_metrics(self):
        client = GrafanaLGTMClient()
        result = await client.query_agent_metrics("security", "duration_ms")
        assert result == []


# ======================================================================
# Dashboard definition tests
# ======================================================================


class TestDashboards:
    def test_agent_dashboard_structure(self):
        dash = shieldops_agent_dashboard()
        assert "dashboard" in dash
        d = dash["dashboard"]
        assert d["title"] == "ShieldOps — Agent Overview"
        assert d["uid"] == "shieldops-agent-overview"
        assert "shieldops" in d["tags"]
        assert len(d["panels"]) == 6
        assert dash["overwrite"] is True

    def test_agent_dashboard_panel_types(self):
        panels = shieldops_agent_dashboard()["dashboard"]["panels"]
        types = {p["type"] for p in panels}
        assert "timeseries" in types
        assert "logs" in types
        assert "gauge" in types
        assert "stat" in types

    def test_sre_dashboard_structure(self):
        dash = shieldops_sre_dashboard()
        d = dash["dashboard"]
        assert d["uid"] == "shieldops-sre-ops"
        assert "sre" in d["tags"]
        assert len(d["panels"]) == 6

    def test_security_dashboard_structure(self):
        dash = shieldops_security_dashboard()
        d = dash["dashboard"]
        assert d["uid"] == "shieldops-security-ops"
        assert "security" in d["tags"]
        assert len(d["panels"]) == 6

    def test_all_dashboards_have_required_fields(self):
        for fn in [
            shieldops_agent_dashboard,
            shieldops_sre_dashboard,
            shieldops_security_dashboard,
        ]:
            dash = fn()
            d = dash["dashboard"]
            assert "title" in d
            assert "uid" in d
            assert "panels" in d
            assert "tags" in d
            assert "time" in d
            for panel in d["panels"]:
                assert "title" in panel
                assert "type" in panel
                assert "gridPos" in panel
                assert "datasource" in panel
                assert "targets" in panel
