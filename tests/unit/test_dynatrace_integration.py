"""Tests for the Dynatrace observability integration."""

from __future__ import annotations

import pytest

from shieldops.integrations.dynatrace.ingest import (
    DynatraceClient,
    DynatraceEvent,
    DynatraceLogEntry,
    DynatraceMetric,
    _escape_dim_value,
    _path_to_bucket,
)
from shieldops.integrations.dynatrace.problems import (
    DynatraceProblemManager,
    DynatraceProblemRule,
    ProblemSeverity,
)


# ---------------------------------------------------------------
# DynatraceMetric
# ---------------------------------------------------------------


class TestDynatraceMetric:
    def test_to_line_protocol_no_dims(self):
        m = DynatraceMetric(key="cpu.usage", value=42.5, timestamp_ms=1700000000000)
        assert m.to_line_protocol() == "cpu.usage gauge,42.5 1700000000000"

    def test_to_line_protocol_with_dims(self):
        m = DynatraceMetric(
            key="shieldops.agent.duration",
            value=1.23,
            dimensions={"agent_type": "investigation", "env": "prod"},
            timestamp_ms=1700000000000,
        )
        line = m.to_line_protocol()
        # Dimensions are sorted by key
        assert line == (
            "shieldops.agent.duration,agent_type=investigation,env=prod"
            " gauge,1.23 1700000000000"
        )

    def test_to_line_protocol_escapes_special_chars(self):
        m = DynatraceMetric(
            key="test.metric",
            value=1.0,
            dimensions={"tag": "a=b,c"},
            timestamp_ms=1700000000000,
        )
        line = m.to_line_protocol()
        assert "a\\=b\\,c" in line

    def test_default_timestamp_is_set(self):
        m = DynatraceMetric(key="x", value=0)
        assert m.timestamp_ms > 0


# ---------------------------------------------------------------
# DynatraceLogEntry
# ---------------------------------------------------------------


class TestDynatraceLogEntry:
    def test_to_payload_minimal(self):
        entry = DynatraceLogEntry(content="hello world")
        p = entry.to_payload()
        assert p["content"] == "hello world"
        assert p["log.source"] == "shieldops"
        assert p["severity"] == "INFO"
        assert "dt.entity.host" not in p

    def test_to_payload_full(self):
        entry = DynatraceLogEntry(
            content="error occurred",
            log_source="my-service",
            log_level="ERROR",
            dt_entity_host_id="HOST-123",
            timestamp="2024-01-01T00:00:00Z",
            attributes={"custom": "value"},
        )
        p = entry.to_payload()
        assert p["dt.entity.host"] == "HOST-123"
        assert p["timestamp"] == "2024-01-01T00:00:00Z"
        assert p["custom"] == "value"
        assert p["severity"] == "ERROR"


# ---------------------------------------------------------------
# DynatraceEvent
# ---------------------------------------------------------------


class TestDynatraceEvent:
    def test_to_payload_defaults(self):
        evt = DynatraceEvent(title="deploy complete")
        p = evt.to_payload()
        assert p["eventType"] == "CUSTOM_INFO"
        assert p["title"] == "deploy complete"
        assert "endTime" not in p  # endTime=0 is omitted

    def test_to_payload_with_entity_selector(self):
        evt = DynatraceEvent(
            title="alert",
            eventType="CUSTOM_ALERT",
            entitySelector="type(HOST)",
            endTime=1700000099000,
        )
        p = evt.to_payload()
        assert p["entitySelector"] == "type(HOST)"
        assert p["endTime"] == 1700000099000


# ---------------------------------------------------------------
# DynatraceClient -- buffered mode
# ---------------------------------------------------------------


class TestDynatraceClientBuffered:
    @pytest.fixture()
    def client(self):
        return DynatraceClient(environment_id="abc12345")

    @pytest.mark.asyncio()
    async def test_send_metrics_buffered(self, client):
        m = DynatraceMetric(key="cpu", value=50.0)
        result = await client.send_metrics([m])
        assert result["status"] == "buffered"
        assert result["count"] == 1
        assert len(client.get_buffered()["metrics"]) == 1

    @pytest.mark.asyncio()
    async def test_send_logs_buffered(self, client):
        entry = DynatraceLogEntry(content="test log")
        result = await client.send_logs([entry])
        assert result["status"] == "buffered"
        assert len(client.get_buffered()["logs"]) == 1

    @pytest.mark.asyncio()
    async def test_send_events_buffered(self, client):
        evt = DynatraceEvent(title="test event")
        result = await client.send_events([evt])
        assert result["status"] == "buffered"
        assert len(client.get_buffered()["events"]) == 1

    @pytest.mark.asyncio()
    async def test_send_traces_buffered(self, client):
        span = {"traceId": "abc", "spanId": "def"}
        result = await client.send_traces([span])
        assert result["status"] == "buffered"
        assert len(client.get_buffered()["traces"]) == 1

    @pytest.mark.asyncio()
    async def test_send_agent_metric(self, client):
        result = await client.send_agent_metric("investigation", "duration", 2.5)
        assert result["status"] == "buffered"
        buf = client.get_buffered()["metrics"]
        assert len(buf) == 1
        assert buf[0]["key"] == "shieldops.agent.duration"
        assert buf[0]["dimensions"]["agent_type"] == "investigation"

    @pytest.mark.asyncio()
    async def test_send_agent_log(self, client):
        result = await client.send_agent_log("security", "WARN", "threat detected")
        assert result["status"] == "buffered"
        buf = client.get_buffered()["logs"]
        assert len(buf) == 1
        assert buf[0]["content"] == "threat detected"

    @pytest.mark.asyncio()
    async def test_send_agent_event(self, client):
        result = await client.send_agent_event(
            "remediation", "rollback initiated", event_type="CUSTOM_ALERT"
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()["events"]
        assert len(buf) == 1
        assert buf[0]["eventType"] == "CUSTOM_ALERT"

    @pytest.mark.asyncio()
    async def test_send_agent_metric_with_extra_dims(self, client):
        result = await client.send_agent_metric(
            "learning", "accuracy", 0.95, dims={"model": "v2"}
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()["metrics"]
        assert buf[0]["dimensions"]["model"] == "v2"

    @pytest.mark.asyncio()
    async def test_send_agent_log_with_attrs(self, client):
        result = await client.send_agent_log(
            "investigation", "ERROR", "timeout", attrs={"incident_id": "INC-42"}
        )
        assert result["status"] == "buffered"

    @pytest.mark.asyncio()
    async def test_send_agent_event_with_props(self, client):
        result = await client.send_agent_event(
            "security", "scan complete", props={"findings": "3"}
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()["events"]
        assert buf[0]["properties"]["findings"] == "3"

    def test_clear_buffer(self, client):
        client._buffer["metrics"].append({"key": "test"})
        client.clear_buffer()
        assert all(len(v) == 0 for v in client.get_buffered().values())

    def test_default_base_url(self, client):
        assert client._base_url == "https://abc12345.live.dynatrace.com"

    def test_custom_base_url(self):
        c = DynatraceClient(base_url="https://custom.example.com")
        assert c._base_url == "https://custom.example.com"

    def test_headers(self):
        c = DynatraceClient(api_token="dt0c01.XXXX")
        headers = c._headers()
        assert headers["Authorization"] == "Api-Token dt0c01.XXXX"
        assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------


class TestHelpers:
    def test_escape_dim_value_plain(self):
        assert _escape_dim_value("hello") == "hello"

    def test_escape_dim_value_special(self):
        assert _escape_dim_value('a=b,c\\d"e') == 'a\\=b\\,c\\\\d\\"e'

    def test_path_to_bucket_metrics(self):
        assert _path_to_bucket("/api/v2/metrics/ingest") == "metrics"

    def test_path_to_bucket_logs(self):
        assert _path_to_bucket("/api/v2/logs/ingest") == "logs"

    def test_path_to_bucket_events(self):
        assert _path_to_bucket("/api/v2/events/ingest") == "events"

    def test_path_to_bucket_traces(self):
        assert _path_to_bucket("/api/v2/otlp/v1/traces") == "traces"


# ---------------------------------------------------------------
# Problem rules
# ---------------------------------------------------------------


class TestDynatraceProblemManager:
    def test_get_default_rules_count(self):
        mgr = DynatraceProblemManager()
        rules = mgr.get_default_rules()
        assert len(rules) == 6

    def test_default_rules_have_required_fields(self):
        mgr = DynatraceProblemManager()
        for rule in mgr.get_default_rules():
            assert rule.name
            assert rule.description
            assert rule.metric_key.startswith("shieldops.")
            assert rule.threshold >= 0
            assert rule.severity in {s.value for s in ProblemSeverity}

    @pytest.mark.asyncio()
    async def test_sync_rules_dry_run(self):
        mgr = DynatraceProblemManager()
        result = await mgr.sync_rules()
        assert result["status"] == "dry_run"
        assert result["count"] == 6

    def test_problem_rule_model(self):
        rule = DynatraceProblemRule(
            name="test",
            description="desc",
            metric_key="shieldops.test",
            threshold=10.0,
        )
        assert rule.severity == ProblemSeverity.CUSTOM_ALERT
        assert rule.aggregation == "AVG"
        assert rule.slide_window_minutes == 10


# ---------------------------------------------------------------
# Package init imports
# ---------------------------------------------------------------


class TestPackageImports:
    def test_import_all_from_init(self):
        from shieldops.integrations.dynatrace import (
            DynatraceClient,
            DynatraceEvent,
            DynatraceLogEntry,
            DynatraceMetric,
            DynatraceProblemManager,
            DynatraceProblemRule,
            ProblemSeverity,
        )
        assert DynatraceClient is not None
        assert ProblemSeverity.ERROR == "ERROR_EVENT"
