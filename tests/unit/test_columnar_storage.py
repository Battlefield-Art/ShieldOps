"""Tests for columnar storage backend."""

from __future__ import annotations

from shieldops.ingest.storage import ColumnarStorage


class TestInsert:
    def test_insert_single_event(self) -> None:
        store = ColumnarStorage()
        store.insert({"category_name": "api_activity", "severity": "low", "message": "test"})
        assert store.get_stats()["total_events"] == 1

    def test_insert_batch(self) -> None:
        store = ColumnarStorage()
        count = store.insert_batch(
            [
                {"category_name": "auth", "severity": "high"},
                {"category_name": "network", "severity": "medium"},
                {"category_name": "finding", "severity": "critical"},
            ]
        )
        assert count == 3
        assert store.get_stats()["total_events"] == 3

    def test_ring_buffer_eviction(self) -> None:
        store = ColumnarStorage(max_events=5)
        for i in range(10):
            store.insert({"message": f"event-{i}"})
        assert store.get_stats()["total_events"] == 5

    def test_event_id_generated(self) -> None:
        store = ColumnarStorage()
        store.insert({"message": "test"})
        events = store.query("SELECT * FROM events LIMIT 1")
        assert events[0]["event_id"] != ""


class TestQuery:
    def test_count_query(self) -> None:
        store = ColumnarStorage()
        store.insert_batch([{"severity": "high"}, {"severity": "low"}, {"severity": "high"}])
        result = store.query("SELECT COUNT(*) FROM events")
        assert result[0]["count"] == 3

    def test_where_equality(self) -> None:
        store = ColumnarStorage()
        store.insert_batch(
            [
                {"severity": "high", "source_provider": "aws"},
                {"severity": "low", "source_provider": "crowdstrike"},
                {"severity": "high", "source_provider": "aws"},
            ]
        )
        result = store.query("SELECT * FROM events WHERE severity = 'high'")
        assert len(result) == 2

    def test_where_source_provider(self) -> None:
        store = ColumnarStorage()
        store.insert_batch(
            [
                {"source_provider": "aws_cloudtrail"},
                {"source_provider": "crowdstrike_fdr"},
                {"source_provider": "aws_cloudtrail"},
            ]
        )
        result = store.query("SELECT * FROM events WHERE source_provider = 'aws_cloudtrail'")
        assert len(result) == 2

    def test_limit(self) -> None:
        store = ColumnarStorage()
        store.insert_batch([{"message": f"e-{i}"} for i in range(20)])
        result = store.query("SELECT * FROM events LIMIT 5")
        assert len(result) == 5

    def test_order_by_severity_desc(self) -> None:
        store = ColumnarStorage()
        store.insert_batch(
            [
                {"severity": "low", "severity_id": 2},
                {"severity": "critical", "severity_id": 5},
                {"severity": "medium", "severity_id": 3},
            ]
        )
        result = store.query("SELECT * FROM events ORDER BY severity_id DESC")
        assert result[0]["severity_id"] == 5
        assert result[-1]["severity_id"] == 2

    def test_empty_store_returns_empty(self) -> None:
        store = ColumnarStorage()
        result = store.query("SELECT * FROM events")
        assert result == []


class TestStats:
    def test_empty_stats(self) -> None:
        store = ColumnarStorage()
        stats = store.get_stats()
        assert stats["total_events"] == 0
        assert stats["storage_backend"] == "memory"

    def test_stats_by_source(self) -> None:
        store = ColumnarStorage()
        store.insert_batch(
            [
                {"source_provider": "aws"},
                {"source_provider": "aws"},
                {"source_provider": "crowdstrike"},
            ]
        )
        stats = store.get_stats()
        assert stats["by_source"]["aws"] == 2
        assert stats["by_source"]["crowdstrike"] == 1

    def test_stats_by_severity(self) -> None:
        store = ColumnarStorage()
        store.insert_batch(
            [
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "low"},
            ]
        )
        stats = store.get_stats()
        assert stats["by_severity"]["high"] == 2
        assert stats["by_severity"]["low"] == 1


class TestRetention:
    def test_retention_removes_old_events(self) -> None:
        store = ColumnarStorage(retention_days=0)  # 0 days = remove everything
        store.insert({"message": "old event", "time": "2020-01-01T00:00:00Z"})
        removed = store.enforce_retention()
        assert removed == 1
        assert store.get_stats()["total_events"] == 0

    def test_retention_keeps_recent_events(self) -> None:
        store = ColumnarStorage(retention_days=365)
        store.insert({"message": "recent"})  # timestamp defaults to now
        removed = store.enforce_retention()
        assert removed == 0
        assert store.get_stats()["total_events"] == 1


class TestClear:
    def test_clear_removes_all(self) -> None:
        store = ColumnarStorage()
        store.insert_batch([{"message": "a"}, {"message": "b"}])
        store.clear()
        assert store.get_stats()["total_events"] == 0
