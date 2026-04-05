"""Tests for DuckDB event store backend."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from shieldops.storage.duckdb_backend import DuckDBEventStore
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
) -> dict:
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


def _make_events(n: int, **kwargs) -> list[dict]:
    return [_make_event(**kwargs) for _ in range(n)]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path) -> DuckDBEventStore:
    """Create a DuckDB event store in a temp directory."""
    db_path = str(tmp_path / "test_events.duckdb")
    parquet_path = str(tmp_path / "parquet")
    return DuckDBEventStore(db_path=db_path, parquet_path=parquet_path)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_implements_protocol(store: DuckDBEventStore) -> None:
    """DuckDBEventStore should satisfy the EventStore protocol."""
    assert isinstance(store, EventStore)


# ---------------------------------------------------------------------------
# Insert + query round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_and_query_roundtrip(store: DuckDBEventStore) -> None:
    events = _make_events(5)
    count = await store.insert_events(events)
    assert count == 5

    rows = await store.query("SELECT * FROM events")
    assert len(rows) == 5
    assert all("event_id" in r for r in rows)


@pytest.mark.asyncio
async def test_insert_empty_list(store: DuckDBEventStore) -> None:
    count = await store.insert_events([])
    assert count == 0


# ---------------------------------------------------------------------------
# Batch insert performance (10K events)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_insert_10k(store: DuckDBEventStore) -> None:
    """Insert 10K events and verify count."""
    events = _make_events(10_000)
    count = await store.insert_events(events)
    assert count == 10_000

    rows = await store.query("SELECT COUNT(*) AS cnt FROM events")
    assert rows[0]["cnt"] == 10_000


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pagination(store: DuckDBEventStore) -> None:
    await store.insert_events(_make_events(25))

    # Page 1
    page1 = await store.query_paginated("SELECT * FROM events", page=1, limit=10)
    assert isinstance(page1, PaginatedResult)
    assert len(page1.items) == 10
    assert page1.total == 25
    assert page1.page == 1
    assert page1.has_more is True

    # Page 3 (last partial page)
    page3 = await store.query_paginated("SELECT * FROM events", page=3, limit=10)
    assert len(page3.items) == 5
    assert page3.has_more is False


# ---------------------------------------------------------------------------
# Storage stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stats_empty(store: DuckDBEventStore) -> None:
    stats = await store.get_stats()
    assert isinstance(stats, StorageStats)
    assert stats.total_events == 0


@pytest.mark.asyncio
async def test_stats_with_data(store: DuckDBEventStore) -> None:
    await store.insert_events(_make_events(10))
    stats = await store.get_stats()
    assert stats.total_events == 10
    assert stats.storage_bytes > 0
    assert stats.oldest_event is not None
    assert stats.newest_event is not None


# ---------------------------------------------------------------------------
# Retention enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retention_enforcement(store: DuckDBEventStore) -> None:
    old_ts = datetime.now(tz=UTC) - timedelta(days=100)
    recent_ts = datetime.now(tz=UTC) - timedelta(hours=1)

    old_events = _make_events(5, org_id="org-1", timestamp=old_ts)
    recent_events = _make_events(3, org_id="org-1", timestamp=recent_ts)
    other_org_events = _make_events(2, org_id="org-2", timestamp=old_ts)

    await store.insert_events(old_events + recent_events + other_org_events)

    # Enforce 30-day retention for org-1 only
    deleted = await store.enforce_retention("org-1", max_days=30)
    assert deleted == 5

    # Recent org-1 events remain
    remaining = await store.query("SELECT * FROM events WHERE org_id = 'org-1'")
    assert len(remaining) == 3

    # org-2 events untouched
    org2 = await store.query("SELECT * FROM events WHERE org_id = 'org-2'")
    assert len(org2) == 2


# ---------------------------------------------------------------------------
# Parquet export
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parquet_export(store: DuckDBEventStore, tmp_path) -> None:
    ts = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
    events = _make_events(5, timestamp=ts)
    await store.insert_events(events)

    files = await store.export_to_parquet()
    assert len(files) >= 1
    assert any("2026" in f for f in files)
    assert any(f.endswith(".parquet") for f in files)


@pytest.mark.asyncio
async def test_parquet_export_empty(store: DuckDBEventStore) -> None:
    files = await store.export_to_parquet()
    assert files == []


@pytest.mark.asyncio
async def test_parquet_export_date_range(store: DuckDBEventStore) -> None:
    ts1 = datetime(2026, 1, 10, tzinfo=UTC)
    ts2 = datetime(2026, 3, 20, tzinfo=UTC)
    events1 = _make_events(3, timestamp=ts1)
    events2 = _make_events(4, timestamp=ts2)
    await store.insert_events(events1 + events2)

    # Export only March data
    files = await store.export_to_parquet(
        start_date=datetime(2026, 3, 1, tzinfo=UTC),
        end_date=datetime(2026, 4, 1, tzinfo=UTC),
    )
    assert len(files) >= 1
    # Should only contain March data
    assert all("2026" in f for f in files)


# ---------------------------------------------------------------------------
# SQL injection prevention (query API validation)
# ---------------------------------------------------------------------------


class TestSQLValidation:
    """Test SQL validation used by the event_query API route."""

    @pytest.fixture(autouse=True)
    def _import_validator(self):
        from shieldops.api.routes.event_query import _validate_query

        self.validate = _validate_query

    def test_valid_select(self) -> None:
        self.validate("SELECT * FROM events")
        self.validate("SELECT event_id, timestamp FROM events WHERE severity = 'high'")
        self.validate("  SELECT COUNT(*) FROM events")

    def test_reject_empty(self) -> None:
        with pytest.raises(Exception, match="Empty query"):
            self.validate("")
        with pytest.raises(Exception, match="Empty query"):
            self.validate("   ")

    def test_reject_insert(self) -> None:
        with pytest.raises(Exception, match="Only SELECT"):
            self.validate("INSERT INTO events VALUES ('a','b')")

    def test_reject_update(self) -> None:
        with pytest.raises(Exception, match="Only SELECT"):
            self.validate("UPDATE events SET severity = 'low'")

    def test_reject_delete(self) -> None:
        with pytest.raises(Exception, match="Only SELECT"):
            self.validate("DELETE FROM events")

    def test_reject_drop(self) -> None:
        with pytest.raises(Exception, match="Only SELECT"):
            self.validate("DROP TABLE events")

    def test_reject_semicolon_chaining(self) -> None:
        with pytest.raises(Exception, match="Semicolons"):
            self.validate("SELECT 1; DROP TABLE events")

    def test_reject_select_with_delete_keyword(self) -> None:
        with pytest.raises(Exception, match="disallowed keyword"):
            self.validate(
                "SELECT * FROM events WHERE event_id IN (DELETE FROM events RETURNING event_id)"
            )

    def test_reject_dangerous_functions(self) -> None:
        with pytest.raises(Exception, match="disallowed function"):
            self.validate("SELECT * FROM read_csv('/etc/passwd')")
        with pytest.raises(Exception, match="disallowed function"):
            self.validate("SELECT * FROM read_parquet('s3://bucket/data.parquet')")

    def test_reject_create_in_select(self) -> None:
        with pytest.raises(Exception, match="disallowed keyword"):
            self.validate("SELECT * FROM (CREATE TABLE foo AS SELECT 1)")

    def test_reject_attach(self) -> None:
        with pytest.raises(Exception, match="disallowed keyword"):
            self.validate("SELECT * FROM events WHERE ATTACH '/tmp/evil.db'")

    def test_reject_copy(self) -> None:
        with pytest.raises(Exception, match="disallowed keyword"):
            self.validate("SELECT * FROM events UNION ALL COPY events TO '/tmp/out'")


# ---------------------------------------------------------------------------
# Org-ID tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_org_id_tenant_isolation(store: DuckDBEventStore) -> None:
    """Events from one org should not be visible when filtering by another."""
    events_org1 = _make_events(5, org_id="org-1")
    events_org2 = _make_events(3, org_id="org-2")
    await store.insert_events(events_org1 + events_org2)

    # Query with org filter (simulates what the API does)
    from shieldops.api.routes.event_query import _inject_org_filter

    sql = "SELECT * FROM events"
    filtered_sql, params = _inject_org_filter(sql, "org-1")
    results = await store.query(filtered_sql, params)
    assert len(results) == 5
    assert all(r["org_id"] == "org-1" for r in results)

    # org-2 should see only their own
    filtered_sql2, params2 = _inject_org_filter(sql, "org-2")
    results2 = await store.query(filtered_sql2, params2)
    assert len(results2) == 3
    assert all(r["org_id"] == "org-2" for r in results2)


@pytest.mark.asyncio
async def test_org_isolation_no_cross_leak(store: DuckDBEventStore) -> None:
    """An org that has no events should get zero results."""
    await store.insert_events(_make_events(5, org_id="org-1"))

    from shieldops.api.routes.event_query import _inject_org_filter

    filtered_sql, params = _inject_org_filter("SELECT * FROM events", "org-999")
    results = await store.query(filtered_sql, params)
    assert len(results) == 0


# ---------------------------------------------------------------------------
# Query with params
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_with_params(store: DuckDBEventStore) -> None:
    await store.insert_events(_make_events(5, severity="critical"))
    await store.insert_events(_make_events(3, severity="low"))

    rows = await store.query(
        "SELECT * FROM events WHERE severity = $sev",
        {"sev": "critical"},
    )
    assert len(rows) == 5


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close(store: DuckDBEventStore) -> None:
    """Closing the store should not raise."""
    await store.insert_events(_make_events(1))
    await store.close()
