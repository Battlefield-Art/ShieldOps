"""Tests for the Honeycomb observability integration."""

from __future__ import annotations

import pytest

from shieldops.integrations.honeycomb.ingest import (
    HoneycombClient,
    HoneycombEvent,
    HoneycombSpan,
)
from shieldops.integrations.honeycomb.queries import (
    HoneycombQuery,
    HoneycombQueryManager,
)


# ------------------------------------------------------------------ #
# Model tests
# ------------------------------------------------------------------ #


class TestHoneycombEvent:
    def test_defaults(self):
        evt = HoneycombEvent()
        assert evt.data == {}
        assert evt.time == ""
        assert evt.samplerate == 1

    def test_with_data(self):
        evt = HoneycombEvent(data={"foo": "bar", "count": 42}, samplerate=5)
        assert evt.data["foo"] == "bar"
        assert evt.samplerate == 5

    def test_with_time(self):
        evt = HoneycombEvent(time="2026-01-01T00:00:00Z")
        assert evt.time == "2026-01-01T00:00:00Z"


class TestHoneycombSpan:
    def test_defaults(self):
        span = HoneycombSpan(name="test.span")
        assert span.name == "test.span"
        assert span.service_name == "shieldops"
        assert span.duration_ms == 0.0
        assert span.status == "ok"
        assert span.attributes == {}

    def test_full_span(self):
        span = HoneycombSpan(
            name="investigate",
            service_name="shieldops-security",
            trace_id="abc123",
            span_id="def456",
            parent_id="000",
            duration_ms=120.5,
            status="error",
            attributes={"node": "triage"},
        )
        assert span.trace_id == "abc123"
        assert span.parent_id == "000"
        assert span.attributes["node"] == "triage"


# ------------------------------------------------------------------ #
# Client -- buffered mode (no API key)
# ------------------------------------------------------------------ #


class TestHoneycombClientBuffered:
    @pytest.fixture()
    def client(self) -> HoneycombClient:
        return HoneycombClient(api_key="", dataset="test-ds")

    @pytest.mark.asyncio()
    async def test_send_event_buffered(self, client: HoneycombClient):
        evt = HoneycombEvent(data={"k": "v"})
        result = await client.send_event(evt)
        assert result["status"] == "buffered"
        assert result["count"] == 1
        assert len(client.get_buffered()) == 1

    @pytest.mark.asyncio()
    async def test_send_batch_buffered(self, client: HoneycombClient):
        events = [
            HoneycombEvent(data={"i": i}) for i in range(5)
        ]
        result = await client.send_batch(events)
        assert result["status"] == "buffered"
        assert result["count"] == 5
        assert len(client.get_buffered()) == 5

    @pytest.mark.asyncio()
    async def test_send_spans_buffered(self, client: HoneycombClient):
        spans = [
            HoneycombSpan(name="span1", duration_ms=10),
            HoneycombSpan(name="span2", duration_ms=20),
        ]
        result = await client.send_spans(spans)
        assert result["status"] == "buffered"
        assert result["count"] == 2

    @pytest.mark.asyncio()
    async def test_send_agent_event_buffered(self, client: HoneycombClient):
        result = await client.send_agent_event(
            agent_type="investigation",
            node_name="triage",
            duration_ms=55.0,
            status="ok",
            confidence=0.92,
            reasoning_steps=3,
            llm_tokens=1500,
            incident_id="INC-001",
        )
        assert result["status"] == "buffered"
        buf = client.get_buffered()
        assert len(buf) == 1
        data = buf[0]
        assert data["agent.type"] == "investigation"
        assert data["agent.node_name"] == "triage"
        assert data["agent.confidence"] == 0.92
        assert data["agent.llm_tokens"] == 1500
        assert data["duration_ms"] == 55.0
        assert data["incident_id"] == "INC-001"
        assert data["platform"] == "shieldops"

    @pytest.mark.asyncio()
    async def test_agent_event_has_wide_fields(self, client: HoneycombClient):
        """Agent events should have 10+ fields (Honeycomb's wide event strength)."""
        await client.send_agent_event(
            agent_type="security",
            node_name="detect",
            duration_ms=100,
            confidence=0.88,
            reasoning_steps=5,
            llm_tokens=2000,
        )
        data = client.get_buffered()[0]
        assert len(data) >= 10

    @pytest.mark.asyncio()
    async def test_send_agent_trace_buffered(self, client: HoneycombClient):
        nodes = [
            {"name": "investigate", "duration_ms": 30, "status": "ok"},
            {"name": "act", "duration_ms": 50, "status": "ok"},
            {"name": "validate", "duration_ms": 20, "status": "ok"},
        ]
        result = await client.send_agent_trace(
            agent_type="remediation",
            request_id="req-123",
            nodes=nodes,
        )
        assert result["status"] == "buffered"
        # Root span + 3 child spans = 4 spans batched
        assert result["count"] == 4
        buf = client.get_buffered()
        assert len(buf) == 4

    @pytest.mark.asyncio()
    async def test_agent_trace_root_span_duration(self, client: HoneycombClient):
        nodes = [
            {"name": "a", "duration_ms": 10},
            {"name": "b", "duration_ms": 20},
        ]
        await client.send_agent_trace("test", "req-1", nodes)
        root = client.get_buffered()[0]
        assert root["data"]["duration_ms"] == 30.0

    @pytest.mark.asyncio()
    async def test_agent_trace_child_spans_have_parent(self, client: HoneycombClient):
        nodes = [{"name": "node1", "duration_ms": 5}]
        await client.send_agent_trace("test", "req-2", nodes)
        buf = client.get_buffered()
        root_span_id = buf[0]["data"]["trace.span_id"]
        child = buf[1]
        assert child["data"]["trace.parent_id"] == root_span_id

    @pytest.mark.asyncio()
    async def test_clear_buffer(self, client: HoneycombClient):
        await client.send_event(HoneycombEvent(data={"x": 1}))
        assert len(client.get_buffered()) == 1
        client.clear_buffer()
        assert len(client.get_buffered()) == 0

    @pytest.mark.asyncio()
    async def test_event_samplerate_in_payload(self, client: HoneycombClient):
        evt = HoneycombEvent(data={"a": 1}, samplerate=10)
        await client.send_event(evt)
        payload = client.get_buffered()[0]
        assert payload.get("samplerate") == 10

    @pytest.mark.asyncio()
    async def test_event_time_in_payload(self, client: HoneycombClient):
        evt = HoneycombEvent(data={"a": 1}, time="2026-03-01T00:00:00Z")
        await client.send_event(evt)
        payload = client.get_buffered()[0]
        assert payload["time"] == "2026-03-01T00:00:00Z"

    @pytest.mark.asyncio()
    async def test_spans_get_trace_ids(self, client: HoneycombClient):
        span = HoneycombSpan(name="test")
        await client.send_spans([span])
        buf = client.get_buffered()
        data = buf[0]["data"]
        assert "trace.trace_id" in data
        assert "trace.span_id" in data
        assert data["trace.trace_id"]  # non-empty

    @pytest.mark.asyncio()
    async def test_default_dataset(self):
        c = HoneycombClient()
        assert c._dataset == "shieldops"

    @pytest.mark.asyncio()
    async def test_custom_api_url(self):
        c = HoneycombClient(api_url="https://custom.honeycomb.example")
        assert c._api_url == "https://custom.honeycomb.example"

    @pytest.mark.asyncio()
    async def test_headers(self):
        c = HoneycombClient(api_key="my-key")
        h = c._headers()
        assert h["X-Honeycomb-Team"] == "my-key"
        assert h["Content-Type"] == "application/json"


# ------------------------------------------------------------------ #
# Query definitions
# ------------------------------------------------------------------ #


class TestHoneycombQuery:
    def test_defaults(self):
        q = HoneycombQuery(name="test")
        assert q.dataset == "shieldops"
        assert q.time_range == 3600
        assert q.calculations == []

    def test_full_query(self):
        q = HoneycombQuery(
            name="q",
            calculations=[{"op": "COUNT"}],
            filters=[{"column": "x", "op": "=", "value": "1"}],
            breakdowns=["agent.type"],
            time_range=7200,
        )
        assert len(q.calculations) == 1
        assert q.breakdowns == ["agent.type"]


class TestHoneycombQueryManager:
    @pytest.fixture()
    def qm(self) -> HoneycombQueryManager:
        return HoneycombQueryManager()

    def test_agent_latency_heatmap(self, qm: HoneycombQueryManager):
        q = qm.agent_latency_heatmap()
        assert q.name == "Agent Latency Heatmap"
        ops = [c["op"] for c in q.calculations]
        assert "HEATMAP" in ops
        assert "agent.type" in q.breakdowns

    def test_agent_error_rate_by_type(self, qm: HoneycombQueryManager):
        q = qm.agent_error_rate_by_type()
        assert "agent.type" in q.breakdowns
        filter_cols = [f["column"] for f in q.filters]
        assert "agent.status" in filter_cols

    def test_llm_token_usage_breakdown(self, qm: HoneycombQueryManager):
        q = qm.llm_token_usage_breakdown()
        ops = [c["op"] for c in q.calculations]
        assert "SUM" in ops
        assert "agent.node_name" in q.breakdowns

    def test_trace_duration_by_node(self, qm: HoneycombQueryManager):
        q = qm.trace_duration_by_node()
        ops = [c["op"] for c in q.calculations]
        assert "P99" in ops

    def test_get_all_queries_count(self, qm: HoneycombQueryManager):
        queries = qm.get_all_queries()
        assert len(queries) == 5
        assert all(isinstance(q, HoneycombQuery) for q in queries)

    def test_all_queries_have_names(self, qm: HoneycombQueryManager):
        for q in qm.get_all_queries():
            assert q.name
            assert q.dataset == "shieldops"
