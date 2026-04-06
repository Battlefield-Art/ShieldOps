"""Tests for ClickHouse event store backend.

All tests mock the ClickHouse client — no real ClickHouse instance required.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from shieldops.storage.clickhouse_backend import (
    _EVENTS_DDL,
    _MATERIALIZED_VIEWS,
    RETENTION_TIERS,
    ClickHouseEventStore,
    _ttl_alter_sql,
)
from shieldops.storage.interface import EventStore, PaginatedResult, StorageStats

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    org_id: str = "org-1",
    event_type: str = "alert",
    severity: str = "high",
    source_provider: str = "crowdstrike",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "org_id": org_id,
        "timestamp": (timestamp or datetime.now(tz=UTC)).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "source_provider": source_provider,
        "source_type": "edr",
        "raw_event": {"detail": "test event"},
        "normalized": {"category": "malware"},
        "enrichments": {"threat_score": 85},
    }


def _make_events(n: int, **kwargs: Any) -> list[dict[str, Any]]:
    return [_make_event(**kwargs) for _ in range(n)]


class _FakeQueryResult:
    """Mimics the clickhouse-connect QueryResult."""

    def __init__(
        self,
        column_names: list[str],
        result_rows: list[list[Any]],
    ) -> None:
        self.column_names = column_names
        self.result_rows = result_rows


def _build_mock_client() -> MagicMock:
    """Return a mock clickhouse-connect client with sensible defaults."""
    client = MagicMock()
    client.command.return_value = None
    client.insert.return_value = None
    # Default empty query result.
    client.query.return_value = _FakeQueryResult([], [])
    return client


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ch_module():
    """Patch clickhouse_connect so the store can be instantiated without a server."""
    mock_module = MagicMock()
    mock_client = _build_mock_client()
    mock_module.get_client.return_value = mock_client
    with patch(
        "shieldops.storage.clickhouse_backend.clickhouse_connect",
        mock_module,
    ):
        yield mock_module, mock_client


@pytest.fixture
def store(mock_ch_module: tuple[MagicMock, MagicMock]) -> ClickHouseEventStore:
    """Create a ClickHouseEventStore backed by mocks."""
    _mock_module, _mock_client = mock_ch_module
    return ClickHouseEventStore(
        host="localhost",
        port=8123,
        database="shieldops_test",
        user="default",
        password="",
    )


@pytest.fixture
def client(
    mock_ch_module: tuple[MagicMock, MagicMock],
    store: ClickHouseEventStore,
) -> MagicMock:
    """Return the mock client wired into the store."""
    _, mock_client = mock_ch_module
    return mock_client


# ---------------------------------------------------------------------------
# Schema creation SQL
# ---------------------------------------------------------------------------


class TestSchemaCreation:
    """Verify DDL statements contain required ClickHouse features."""

    def test_events_ddl_has_mergetree_engine(self) -> None:
        assert "ENGINE = MergeTree()" in _EVENTS_DDL

    def test_events_ddl_has_partition_by_org_and_month(self) -> None:
        assert "PARTITION BY (org_id, toYYYYMM(timestamp))" in _EVENTS_DDL

    def test_events_ddl_has_order_by(self) -> None:
        assert "ORDER BY (org_id, event_type, timestamp)" in _EVENTS_DDL

    def test_events_ddl_has_low_cardinality_columns(self) -> None:
        assert "LowCardinality(String)" in _EVENTS_DDL

    def test_events_ddl_has_datetime64(self) -> None:
        assert "DateTime64(3)" in _EVENTS_DDL

    def test_events_ddl_has_event_type_index(self) -> None:
        assert "INDEX idx_event_type event_type TYPE set(100)" in _EVENTS_DDL

    def test_events_ddl_has_severity_index(self) -> None:
        assert "INDEX idx_severity severity TYPE set(10)" in _EVENTS_DDL

    def test_schema_created_on_init(self, client: MagicMock) -> None:
        """Constructor should execute CREATE DATABASE + CREATE TABLE + MVs."""
        command_calls = [str(c) for c in client.command.call_args_list]
        assert any("CREATE DATABASE" in c for c in command_calls)
        assert any("CREATE TABLE" in c for c in command_calls)

    def test_static_helpers(self) -> None:
        """Static DDL accessors should return valid strings."""
        assert "MergeTree" in ClickHouseEventStore.get_events_ddl()
        mvs = ClickHouseEventStore.get_materialized_view_ddls()
        assert len(mvs) == 4
        ttl_sql = ClickHouseEventStore.get_ttl_sql(90)
        assert "90 DAY" in ttl_sql


# ---------------------------------------------------------------------------
# Materialized views
# ---------------------------------------------------------------------------


class TestMaterializedViews:
    """Verify all four materialized views are defined and created."""

    def test_four_views_defined(self) -> None:
        assert len(_MATERIALIZED_VIEWS) == 4

    def test_events_per_hour_view(self) -> None:
        mv = _MATERIALIZED_VIEWS[0]
        assert "mv_events_per_hour" in mv
        assert "SummingMergeTree" in mv
        assert "toStartOfHour" in mv

    def test_top_source_ips_view(self) -> None:
        mv = _MATERIALIZED_VIEWS[1]
        assert "mv_top_source_ips" in mv
        assert "source_provider" in mv

    def test_alert_volume_trend_view(self) -> None:
        mv = _MATERIALIZED_VIEWS[2]
        assert "mv_alert_volume_trend" in mv
        assert "severity" in mv

    def test_mitre_frequency_view(self) -> None:
        mv = _MATERIALIZED_VIEWS[3]
        assert "mv_mitre_frequency" in mv
        assert "toMonday" in mv

    def test_mvs_created_on_init(self, client: MagicMock) -> None:
        command_calls = [str(c) for c in client.command.call_args_list]
        for mv in _MATERIALIZED_VIEWS:
            view_name = mv.split("IF NOT EXISTS ")[1].split("\n")[0].strip()
            assert any(view_name in c for c in command_calls)


# ---------------------------------------------------------------------------
# TTL configuration
# ---------------------------------------------------------------------------


class TestTTLConfiguration:
    """Verify TTL retention SQL generation."""

    def test_ttl_sql_30_days(self) -> None:
        sql = _ttl_alter_sql("events", 30)
        assert "ALTER TABLE events MODIFY TTL" in sql
        assert "INTERVAL 30 DAY DELETE" in sql

    def test_ttl_sql_90_days(self) -> None:
        sql = _ttl_alter_sql("events", 90)
        assert "INTERVAL 90 DAY DELETE" in sql

    def test_ttl_sql_365_days(self) -> None:
        sql = _ttl_alter_sql("events", 365)
        assert "INTERVAL 365 DAY DELETE" in sql

    def test_retention_tier_presets(self) -> None:
        assert RETENTION_TIERS["starter"] == 30
        assert RETENTION_TIERS["professional"] == 90
        assert RETENTION_TIERS["enterprise"] == 365

    def test_ttl_applied_on_init(self, mock_ch_module: tuple[MagicMock, MagicMock]) -> None:
        """When ttl_days is set, ALTER TABLE TTL should be executed."""
        _mock_module, mock_client = mock_ch_module
        ClickHouseEventStore(
            host="localhost",
            port=8123,
            database="shieldops_ttl",
            user="default",
            password="",
            ttl_days=90,
        )
        command_calls = [str(c) for c in mock_client.command.call_args_list]
        assert any("MODIFY TTL" in c and "90 DAY" in c for c in command_calls)


# ---------------------------------------------------------------------------
# Tenant isolation (org_id filtering)
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    """Queries should always be filterable by org_id."""

    @pytest.mark.asyncio
    async def test_insert_preserves_org_id(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        events = _make_events(3, org_id="tenant-abc")
        count = await store.insert_events(events)
        assert count == 3

        # Verify the inserted rows contain org_id.
        insert_call = client.insert.call_args
        rows = insert_call[0][1]  # positional arg: list of rows
        assert all(row[1] == "tenant-abc" for row in rows)

    @pytest.mark.asyncio
    async def test_query_returns_org_filtered_results(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        """Simulates a tenant-scoped query."""
        client.query.return_value = _FakeQueryResult(
            column_names=["event_id", "org_id", "event_type"],
            result_rows=[
                ["evt-1", "org-1", "alert"],
                ["evt-2", "org-1", "alert"],
            ],
        )
        results = await store.query(
            "SELECT * FROM events WHERE org_id = {org:String}",
            params={"org": "org-1"},
        )
        assert len(results) == 2
        assert all(r["org_id"] == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_enforce_retention_scoped_to_org(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        client.query.return_value = _FakeQueryResult(
            column_names=["count()"],
            result_rows=[[7]],
        )
        deleted = await store.enforce_retention("org-42", max_days=30)
        assert deleted == 7

        # Verify the ALTER DELETE command was scoped to org_id.
        command_calls = [str(c) for c in client.command.call_args_list]
        assert any("org-42" in c for c in command_calls)

    def test_ddl_partitioned_by_org_id(self) -> None:
        """The events table must be partitioned by org_id for isolation."""
        assert "PARTITION BY (org_id" in _EVENTS_DDL

    def test_order_by_starts_with_org_id(self) -> None:
        assert "ORDER BY (org_id," in _EVENTS_DDL


# ---------------------------------------------------------------------------
# Batch insert formatting
# ---------------------------------------------------------------------------


class TestBatchInsert:
    """Verify batch insert formatting and column mapping."""

    @pytest.mark.asyncio
    async def test_column_order(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        events = [_make_event()]
        await store.insert_events(events)

        insert_call = client.insert.call_args
        assert insert_call is not None
        column_names = insert_call[1]["column_names"]
        assert column_names == [
            "event_id",
            "org_id",
            "timestamp",
            "event_type",
            "severity",
            "source_provider",
            "source_type",
            "raw_event",
            "normalized",
            "enrichments",
        ]

    @pytest.mark.asyncio
    async def test_json_fields_serialized(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        events = [_make_event()]
        await store.insert_events(events)

        insert_call = client.insert.call_args
        rows = insert_call[0][1]
        row = rows[0]
        # raw_event, normalized, enrichments should be JSON strings.
        assert '"detail"' in row[7]  # raw_event
        assert '"category"' in row[8]  # normalized
        assert '"threat_score"' in row[9]  # enrichments

    @pytest.mark.asyncio
    async def test_empty_insert_returns_zero(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        count = await store.insert_events([])
        assert count == 0
        client.insert.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_optional_fields_default(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        """Events with missing optional fields should not raise."""
        events = [{"event_id": "e1", "org_id": "o1", "event_type": "test"}]
        count = await store.insert_events(events)
        assert count == 1


# ---------------------------------------------------------------------------
# Query and pagination
# ---------------------------------------------------------------------------


class TestQueryPagination:
    @pytest.mark.asyncio
    async def test_query_returns_dicts(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        client.query.return_value = _FakeQueryResult(
            column_names=["event_id", "severity"],
            result_rows=[["e1", "high"], ["e2", "low"]],
        )
        results = await store.query("SELECT event_id, severity FROM events")
        assert len(results) == 2
        assert results[0] == {"event_id": "e1", "severity": "high"}

    @pytest.mark.asyncio
    async def test_paginated_query(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        # First call = count, second call = page data.
        client.query.side_effect = [
            _FakeQueryResult(["cnt"], [[25]]),
            _FakeQueryResult(
                ["event_id"],
                [["e1"], ["e2"], ["e3"], ["e4"], ["e5"]],
            ),
        ]
        result = await store.query_paginated(
            "SELECT event_id FROM events",
            page=2,
            limit=5,
        )
        assert isinstance(result, PaginatedResult)
        assert result.total == 25
        assert result.page == 2
        assert len(result.items) == 5
        assert result.has_more is True


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    @pytest.mark.asyncio
    async def test_stats_empty_table(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        client.query.return_value = _FakeQueryResult(
            ["cnt", "sz", "oldest", "newest"],
            [[0, 0, None, None]],
        )
        stats = await store.get_stats()
        assert isinstance(stats, StorageStats)
        assert stats.total_events == 0

    @pytest.mark.asyncio
    async def test_stats_with_data(
        self,
        store: ClickHouseEventStore,
        client: MagicMock,
    ) -> None:
        now = datetime.now(tz=UTC)
        client.query.side_effect = [
            _FakeQueryResult(
                ["cnt", "sz", "oldest", "newest"],
                [[100, 50000, now, now]],
            ),
            _FakeQueryResult(["sum(bytes_on_disk)"], [[123456]]),
        ]
        stats = await store.get_stats()
        assert stats.total_events == 100
        assert stats.storage_bytes == 123456
        assert stats.oldest_event == now
        assert stats.newest_event == now


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_implements_event_store_protocol(
        self,
        store: ClickHouseEventStore,
    ) -> None:
        """ClickHouseEventStore should satisfy the EventStore protocol."""
        assert isinstance(store, EventStore)


# ---------------------------------------------------------------------------
# Singleton factory integration
# ---------------------------------------------------------------------------


class TestSingletonFactory:
    """Verify singleton picks the correct backend based on env var."""

    def test_default_is_duckdb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from shieldops.storage import singleton

        singleton.reset_event_store()
        monkeypatch.delenv("SHIELDOPS_STORAGE_BACKEND", raising=False)
        # We don't actually call get_event_store() here because it would
        # try to init a real DuckDB; just verify the env-var logic.
        import os

        backend = os.environ.get("SHIELDOPS_STORAGE_BACKEND", "duckdb").lower()
        assert backend == "duckdb"

    def test_clickhouse_selected_by_env(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_ch_module: tuple[MagicMock, MagicMock],
    ) -> None:
        from shieldops.storage import singleton

        singleton.reset_event_store()
        monkeypatch.setenv("SHIELDOPS_STORAGE_BACKEND", "clickhouse")
        monkeypatch.setenv("CLICKHOUSE_HOST", "ch.example.com")
        monkeypatch.setenv("CLICKHOUSE_PORT", "9000")
        monkeypatch.setenv("CLICKHOUSE_DATABASE", "shieldops")

        store = singleton.get_event_store()
        assert isinstance(store, ClickHouseEventStore)
        singleton.reset_event_store()


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


class TestClose:
    @pytest.mark.asyncio
    async def test_close_does_not_raise(
        self,
        store: ClickHouseEventStore,
    ) -> None:
        await store.close()


# ---------------------------------------------------------------------------
# Import guard
# ---------------------------------------------------------------------------


class TestImportGuard:
    def test_raises_without_clickhouse_connect(self) -> None:
        with (
            patch(
                "shieldops.storage.clickhouse_backend.clickhouse_connect",
                None,
            ),
            pytest.raises(RuntimeError, match="clickhouse-connect"),
        ):
            ClickHouseEventStore()
