"""Tests for Datadog observability integration."""

from __future__ import annotations

import pytest

from shieldops.integrations.datadog.ingest import (
    DatadogClient,
    DatadogLogEntry,
    DatadogMetricPoint,
    DatadogMetricType,
    DatadogSpan,
)
from shieldops.integrations.datadog.monitors import (
    DatadogMonitor,
    DatadogMonitorManager,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestDatadogMetricType:
    def test_gauge_value(self) -> None:
        assert DatadogMetricType.GAUGE == "gauge"

    def test_rate_value(self) -> None:
        assert DatadogMetricType.RATE == "rate"

    def test_count_value(self) -> None:
        assert DatadogMetricType.COUNT == "count"


class TestDatadogLogEntry:
    def test_defaults(self) -> None:
        entry = DatadogLogEntry(message="hello")
        assert entry.ddsource == "shieldops"
        assert entry.status == "info"
        assert entry.timestamp > 0

    def test_custom_fields(self) -> None:
        entry = DatadogLogEntry(
            message="test",
            ddsource="myapp",
            ddtags="env:prod",
            hostname="host1",
            service="api",
            status="error",
        )
        assert entry.service == "api"
        assert entry.ddtags == "env:prod"


class TestDatadogMetricPoint:
    def test_defaults(self) -> None:
        m = DatadogMetricPoint(metric="cpu.usage")
        assert m.type == DatadogMetricType.GAUGE
        assert m.tags == []
        assert m.points == []

    def test_with_points_and_tags(self) -> None:
        m = DatadogMetricPoint(
            metric="mem.used",
            type=DatadogMetricType.COUNT,
            points=[{"timestamp": 1000, "value": 42.0}],
            tags=["env:test"],
            unit="bytes",
        )
        assert m.type == DatadogMetricType.COUNT
        assert len(m.points) == 1
        assert m.unit == "bytes"


class TestDatadogSpan:
    def test_defaults(self) -> None:
        s = DatadogSpan(trace_id=1, span_id=2, name="op")
        assert s.service == "shieldops"
        assert s.parent_id == 0
        assert s.duration == 0
        assert s.start > 0

    def test_custom_fields(self) -> None:
        s = DatadogSpan(
            trace_id=10,
            span_id=20,
            parent_id=5,
            name="query",
            service="db",
            resource="/api/v1/foo",
            duration=500_000,
            meta={"key": "val"},
        )
        assert s.resource == "/api/v1/foo"
        assert s.meta["key"] == "val"


# ---------------------------------------------------------------------------
# Client tests (buffered mode -- no API key)
# ---------------------------------------------------------------------------


class TestDatadogClientInit:
    def test_default_urls(self) -> None:
        c = DatadogClient()
        assert "datadoghq.com" in c._logs_url
        assert "datadoghq.com" in c._metrics_url
        assert "datadoghq.com" in c._traces_url

    def test_custom_site(self) -> None:
        c = DatadogClient(site="datadoghq.eu")
        assert "datadoghq.eu" in c._logs_url

    def test_headers_without_app_key(self) -> None:
        c = DatadogClient(api_key="test-key")
        h = c._headers()
        assert h["DD-API-KEY"] == "test-key"
        assert "DD-APPLICATION-KEY" not in h

    def test_headers_with_app_key(self) -> None:
        c = DatadogClient(api_key="ak", app_key="appk")
        h = c._headers()
        assert h["DD-APPLICATION-KEY"] == "appk"


class TestDatadogClientBufferedLogs:
    @pytest.mark.asyncio
    async def test_send_logs_buffered(self) -> None:
        c = DatadogClient()
        entry = DatadogLogEntry(message="test log")
        result = await c.send_logs([entry])
        assert result["status"] == "buffered"
        assert result["count"] == 1
        assert len(c.get_buffered()["logs"]) == 1

    @pytest.mark.asyncio
    async def test_send_agent_log_buffered(self) -> None:
        c = DatadogClient()
        result = await c.send_agent_log("investigation", "info", "started")
        assert result["status"] == "buffered"
        buf = c.get_buffered()["logs"]
        assert len(buf) == 1
        assert buf[0]["ddsource"] == "shieldops"
        assert "agent_type:investigation" in buf[0]["ddtags"]


class TestDatadogClientBufferedMetrics:
    @pytest.mark.asyncio
    async def test_send_metrics_buffered(self) -> None:
        c = DatadogClient()
        m = DatadogMetricPoint(
            metric="test.metric",
            points=[{"timestamp": 1000, "value": 1.5}],
        )
        result = await c.send_metrics([m])
        assert result["status"] == "buffered"
        assert len(c.get_buffered()["metrics"]) == 1

    @pytest.mark.asyncio
    async def test_send_agent_metric_buffered(self) -> None:
        c = DatadogClient()
        result = await c.send_agent_metric("remediation", "success_rate", 0.95)
        assert result["status"] == "buffered"
        buf = c.get_buffered()["metrics"]
        assert len(buf) == 1
        series = buf[0]["series"][0]
        assert series["metric"] == "shieldops.agent.success_rate"
        assert "agent_type:remediation" in series["tags"]


class TestDatadogClientBufferedTraces:
    @pytest.mark.asyncio
    async def test_send_traces_buffered(self) -> None:
        c = DatadogClient()
        span = DatadogSpan(trace_id=1, span_id=2, name="test.op")
        result = await c.send_traces([span])
        assert result["status"] == "buffered"
        assert len(c.get_buffered()["traces"]) == 1

    @pytest.mark.asyncio
    async def test_send_traces_groups_by_trace_id(self) -> None:
        c = DatadogClient()
        spans = [
            DatadogSpan(trace_id=1, span_id=10, name="a"),
            DatadogSpan(trace_id=1, span_id=11, name="b"),
            DatadogSpan(trace_id=2, span_id=20, name="c"),
        ]
        result = await c.send_traces(spans)
        assert result["status"] == "buffered"
        # Should produce 2 trace groups
        assert len(c.get_buffered()["traces"]) == 2

    @pytest.mark.asyncio
    async def test_send_agent_span_buffered(self) -> None:
        c = DatadogClient()
        result = await c.send_agent_span(
            agent_type="security",
            operation="investigate",
            trace_id=100,
            span_id=200,
            duration_ns=5_000_000,
        )
        assert result["status"] == "buffered"
        buf = c.get_buffered()["traces"]
        assert len(buf) == 1
        # trace group is a list of spans
        span = buf[0][0]
        assert span["name"] == "security.investigate"
        assert span["duration"] == 5_000_000


class TestDatadogClientClearBuffer:
    @pytest.mark.asyncio
    async def test_clear_buffer(self) -> None:
        c = DatadogClient()
        await c.send_logs([DatadogLogEntry(message="x")])
        assert len(c.get_buffered()["logs"]) == 1
        c.clear_buffer()
        assert c.get_buffered() == {"logs": [], "metrics": [], "traces": []}


# ---------------------------------------------------------------------------
# Monitor tests
# ---------------------------------------------------------------------------


class TestDatadogMonitorModel:
    def test_defaults(self) -> None:
        m = DatadogMonitor(name="test", query="avg:cpu{*} > 90", message="alert")
        assert m.type == "metric alert"
        assert m.priority == 3
        assert m.tags == []

    def test_custom_fields(self) -> None:
        m = DatadogMonitor(
            name="test",
            query="q",
            message="m",
            tags=["team:sre"],
            priority=1,
            thresholds={"critical": 100},
        )
        assert m.thresholds["critical"] == 100


class TestDatadogMonitorManager:
    def test_get_default_monitors_returns_six(self) -> None:
        mgr = DatadogMonitorManager()
        monitors = mgr.get_default_monitors()
        assert len(monitors) == 6

    def test_default_monitors_have_required_fields(self) -> None:
        mgr = DatadogMonitorManager()
        for m in mgr.get_default_monitors():
            assert m.name
            assert m.query
            assert m.message
            assert m.tags
            assert m.thresholds

    def test_monitor_names_are_unique(self) -> None:
        mgr = DatadogMonitorManager()
        names = [m.name for m in mgr.get_default_monitors()]
        assert len(names) == len(set(names))

    @pytest.mark.asyncio
    async def test_sync_monitors_dry_run(self) -> None:
        mgr = DatadogMonitorManager()
        result = await mgr.sync_monitors()
        assert result["status"] == "dry_run"
        assert result["count"] == 6


# ---------------------------------------------------------------------------
# Package init / import tests
# ---------------------------------------------------------------------------


class TestPackageImports:
    def test_import_all_from_package(self) -> None:
        from shieldops.integrations.datadog import (
            DatadogClient,
            DatadogLogEntry,
            DatadogMetricPoint,
            DatadogMetricType,
            DatadogMonitor,
            DatadogMonitorManager,
            DatadogSpan,
        )

        assert DatadogClient is not None
        assert DatadogMonitorManager is not None
