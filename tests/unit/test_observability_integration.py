"""Tests for the observability integration layer.

Covers IngestClient (all backends), AgentTelemetryCollector, and dashboard definitions.
"""

from __future__ import annotations

import pytest

from shieldops.integrations.observability.agent_telemetry import (
    AgentTelemetryCollector,
)
from shieldops.integrations.observability.dashboards import (
    agent_overview_dashboard,
    incident_timeline_dashboard,
    llm_cost_dashboard,
)
from shieldops.integrations.observability.ingest import (
    IngestResult,
    ObservabilityBackend,
    ObservabilityIngestClient,
    SignalType,
    TelemetryRecord,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def local_client() -> ObservabilityIngestClient:
    return ObservabilityIngestClient(backend=ObservabilityBackend.LOCAL)


@pytest.fixture
def openobserve_client() -> ObservabilityIngestClient:
    return ObservabilityIngestClient(
        backend=ObservabilityBackend.OPENOBSERVE,
        base_url="http://localhost:5080",
        username="admin",
        password="secret",
    )


@pytest.fixture
def elasticsearch_client() -> ObservabilityIngestClient:
    return ObservabilityIngestClient(
        backend=ObservabilityBackend.ELASTICSEARCH,
        base_url="http://localhost:9200",
    )


@pytest.fixture
def collector(local_client: ObservabilityIngestClient) -> AgentTelemetryCollector:
    return AgentTelemetryCollector(ingest_client=local_client)


# ── IngestClient Initialization ──────────────────────────────────────


class TestIngestClientInit:
    def test_init_local_backend(self, local_client: ObservabilityIngestClient) -> None:
        assert local_client.backend == ObservabilityBackend.LOCAL
        assert local_client.organization == "shieldops"
        assert local_client.max_batch_size == 1000

    def test_init_openobserve_backend(self, openobserve_client: ObservabilityIngestClient) -> None:
        assert openobserve_client.backend == ObservabilityBackend.OPENOBSERVE
        assert openobserve_client._auth_header.startswith("Basic ")

    def test_init_elasticsearch_backend(
        self, elasticsearch_client: ObservabilityIngestClient
    ) -> None:
        assert elasticsearch_client.backend == ObservabilityBackend.ELASTICSEARCH
        assert elasticsearch_client._auth_header == ""

    def test_init_custom_params(self) -> None:
        client = ObservabilityIngestClient(
            backend=ObservabilityBackend.LOCAL,
            organization="custom_org",
            max_batch_size=500,
            max_buffer_size=10_000,
        )
        assert client.organization == "custom_org"
        assert client.max_batch_size == 500
        assert client.max_buffer_size == 10_000


# ── Local Backend Ingestion ──────────────────────────────────────────


class TestLocalIngest:
    @pytest.mark.asyncio
    async def test_ingest_logs(self, local_client: ObservabilityIngestClient) -> None:
        result = await local_client.ingest_logs(
            "test_stream",
            [{"message": "hello", "level": "info"}],
        )
        assert isinstance(result, IngestResult)
        assert result.successful == 1
        assert result.failed == 0
        assert result.stream == "test_stream"
        assert local_client.get_local_stream_count("test_stream") == 1

    @pytest.mark.asyncio
    async def test_ingest_metrics(self, local_client: ObservabilityIngestClient) -> None:
        result = await local_client.ingest_metrics(
            "metric_stream",
            [
                {"metric_name": "cpu_usage", "value": 0.75},
                {"metric_name": "mem_usage", "value": 0.60},
            ],
        )
        assert result.successful == 2
        assert result.failed == 0
        assert local_client.get_local_stream_count("metric_stream") == 2

    @pytest.mark.asyncio
    async def test_ingest_traces(self, local_client: ObservabilityIngestClient) -> None:
        result = await local_client.ingest_traces(
            "trace_stream",
            [{"trace_id": "abc123", "span_id": "span1", "operation": "test"}],
        )
        assert result.successful == 1
        assert result.failed == 0

    @pytest.mark.asyncio
    async def test_ingest_empty_records(self, local_client: ObservabilityIngestClient) -> None:
        result = await local_client.ingest_logs("empty_stream", [])
        assert result.successful == 0
        assert result.failed == 0

    @pytest.mark.asyncio
    async def test_ingest_agent_event(self, local_client: ObservabilityIngestClient) -> None:
        result = await local_client.ingest_agent_event(
            agent_type="investigation",
            event_type="alert_received",
            data={"alert_id": "ALT-001", "severity": "high"},
            level="warn",
        )
        assert result.successful == 1
        assert "agent_investigation" in local_client.get_local_stream_names()

    @pytest.mark.asyncio
    async def test_ring_buffer_eviction(self) -> None:
        client = ObservabilityIngestClient(backend=ObservabilityBackend.LOCAL, max_buffer_size=5)
        records = [{"msg": f"record_{i}"} for i in range(10)]
        await client.ingest_logs("bounded", records)
        assert client.get_local_stream_count("bounded") == 5


# ── Local Backend Querying ───────────────────────────────────────────


class TestLocalQuery:
    @pytest.mark.asyncio
    async def test_query_logs_returns_results(
        self, local_client: ObservabilityIngestClient
    ) -> None:
        await local_client.ingest_logs(
            "query_test",
            [
                {"level": "info", "msg": "first"},
                {"level": "error", "msg": "second"},
            ],
        )
        results = await local_client.query_logs("query_test", "SELECT * FROM query_test")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_logs_with_where_filter(
        self, local_client: ObservabilityIngestClient
    ) -> None:
        await local_client.ingest_logs(
            "filter_test",
            [
                {"level": "info", "msg": "ok"},
                {"level": "error", "msg": "bad"},
                {"level": "info", "msg": "fine"},
            ],
        )
        results = await local_client.query_logs(
            "filter_test", "SELECT * FROM filter_test WHERE level = 'error'"
        )
        assert len(results) == 1
        assert results[0]["msg"] == "bad"

    @pytest.mark.asyncio
    async def test_query_logs_with_limit(self, local_client: ObservabilityIngestClient) -> None:
        await local_client.ingest_logs(
            "limit_test",
            [{"msg": f"r{i}"} for i in range(10)],
        )
        results = await local_client.query_logs("limit_test", "SELECT * FROM limit_test LIMIT 3")
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_query_nonexistent_stream(self, local_client: ObservabilityIngestClient) -> None:
        results = await local_client.query_logs("no_such_stream", "SELECT *")
        assert results == []

    @pytest.mark.asyncio
    async def test_query_metrics(self, local_client: ObservabilityIngestClient) -> None:
        await local_client.ingest_metrics(
            "m_stream",
            [
                {"metric_name": "cpu_usage", "value": 0.8},
                {"metric_name": "mem_usage", "value": 0.6},
            ],
        )
        results = await local_client.query_metrics("cpu_usage")
        assert len(results) == 1
        assert results[0]["metric_name"] == "cpu_usage"


# ── Agent Telemetry Collector ────────────────────────────────────────


class TestAgentTelemetryCollector:
    @pytest.mark.asyncio
    async def test_record_agent_start(
        self,
        collector: AgentTelemetryCollector,
        local_client: ObservabilityIngestClient,
    ) -> None:
        await collector.record_agent_start(
            agent_type="investigation",
            request_id="req-001",
            input_data={"alert_id": "ALT-1"},
        )
        assert local_client.get_local_stream_count("agent_logs") >= 1
        assert local_client.get_local_stream_count("agent_traces") >= 1
        assert "req-001" in collector._active_traces

    @pytest.mark.asyncio
    async def test_record_node_execution(
        self,
        collector: AgentTelemetryCollector,
        local_client: ObservabilityIngestClient,
    ) -> None:
        await collector.record_agent_start("investigation", "req-002", {})
        await collector.record_node_execution(
            agent_type="investigation",
            request_id="req-002",
            node_name="gather_context",
            duration_ms=150,
            status="success",
            output_summary="Gathered 5 related alerts",
        )
        assert local_client.get_local_stream_count("agent_metrics") >= 1

    @pytest.mark.asyncio
    async def test_record_agent_complete(
        self,
        collector: AgentTelemetryCollector,
        local_client: ObservabilityIngestClient,
    ) -> None:
        await collector.record_agent_start("remediation", "req-003", {})
        await collector.record_agent_complete(
            agent_type="remediation",
            request_id="req-003",
            status="success",
            duration_ms=2500,
            reasoning_steps=4,
            confidence=0.92,
        )
        # Trace should be cleaned up
        assert "req-003" not in collector._active_traces
        # Metrics emitted
        assert local_client.get_local_stream_count("agent_metrics") >= 1

    @pytest.mark.asyncio
    async def test_record_llm_call(
        self,
        collector: AgentTelemetryCollector,
        local_client: ObservabilityIngestClient,
    ) -> None:
        await collector.record_llm_call(
            agent_type="security",
            node_name="analyze_threat",
            model="claude-sonnet-4-20250514",
            input_tokens=1200,
            output_tokens=800,
            latency_ms=340,
        )
        assert local_client.get_local_stream_count("llm_logs") == 1
        assert local_client.get_local_stream_count("llm_metrics") >= 1


# ── Dashboard Definitions ────────────────────────────────────────────


class TestDashboards:
    def test_agent_overview_dashboard_structure(self) -> None:
        dash = agent_overview_dashboard()
        assert isinstance(dash, dict)
        assert dash["title"] == "ShieldOps Agent Overview"
        assert "panels" in dash
        assert len(dash["panels"]) >= 4
        for panel in dash["panels"]:
            assert "title" in panel
            assert "type" in panel
            assert "config" in panel
            assert "queries" in panel["config"]

    def test_llm_cost_dashboard_structure(self) -> None:
        dash = llm_cost_dashboard()
        assert isinstance(dash, dict)
        assert dash["title"] == "LLM Cost & Token Usage"
        assert len(dash["panels"]) >= 4
        # Verify cost panel exists
        titles = [p["title"] for p in dash["panels"]]
        assert any("cost" in t.lower() or "token" in t.lower() for t in titles)

    def test_incident_timeline_dashboard_structure(self) -> None:
        dash = incident_timeline_dashboard()
        assert isinstance(dash, dict)
        assert "Incident" in dash["title"]
        assert len(dash["panels"]) >= 4
        titles = [p["title"] for p in dash["panels"]]
        assert any("MTTD" in t or "MTTR" in t for t in titles)


# ── Pydantic Model Validation ────────────────────────────────────────


class TestModels:
    def test_telemetry_record_defaults(self) -> None:
        rec = TelemetryRecord(signal_type=SignalType.LOGS, stream="test")
        assert rec.signal_type == SignalType.LOGS
        assert rec.stream == "test"
        assert rec.timestamp_us > 0
        assert rec.level == "info"
        assert rec.data == {}

    def test_ingest_result_validation(self) -> None:
        result = IngestResult(stream="s", successful=5, failed=2, status_code=207)
        assert result.stream == "s"
        assert result.successful == 5
        assert result.failed == 2
        assert result.status_code == 207

    def test_signal_type_enum(self) -> None:
        assert SignalType.LOGS == "logs"
        assert SignalType.METRICS == "metrics"
        assert SignalType.TRACES == "traces"

    def test_backend_enum(self) -> None:
        assert ObservabilityBackend.OPENOBSERVE == "openobserve"
        assert ObservabilityBackend.ELASTICSEARCH == "elasticsearch"
        assert ObservabilityBackend.LOCAL == "local"
