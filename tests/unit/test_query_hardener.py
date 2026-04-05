"""Tests for NL query hardening — cache, audit, export, templates."""

from __future__ import annotations

from unittest.mock import patch

from shieldops.ingest.query_hardener import (
    QUERY_TEMPLATES,
    QueryAuditLog,
    QueryCache,
    export_to_csv,
    export_to_json,
    export_to_markdown,
)


class TestQueryCache:
    def test_set_and_get(self) -> None:
        cache = QueryCache()
        cache.set("key1", {"data": [1, 2, 3]})
        assert cache.get("key1") == {"data": [1, 2, 3]}

    def test_miss_returns_none(self) -> None:
        cache = QueryCache()
        assert cache.get("missing") is None

    def test_expired_returns_none(self) -> None:
        cache = QueryCache(ttl_seconds=0)
        cache.set("key1", "value")
        with patch("shieldops.ingest.query_hardener.time") as mock_time:
            mock_time.monotonic.return_value = 999999999
            assert cache.get("key1") is None

    def test_evicts_oldest_at_max(self) -> None:
        cache = QueryCache(max_entries=2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)  # should evict "a"
        assert cache.size == 2
        assert cache.get("c") == 3

    def test_make_key_deterministic(self) -> None:
        cache = QueryCache()
        k1 = cache.make_key("SELECT * FROM events LIMIT 10")
        k2 = cache.make_key("select * from events limit 10")
        assert k1 == k2  # case-insensitive

    def test_clear(self) -> None:
        cache = QueryCache()
        cache.set("a", 1)
        cache.clear()
        assert cache.size == 0


class TestQueryAuditLog:
    def test_record_and_retrieve(self) -> None:
        log = QueryAuditLog()
        log.record("test question", "SELECT 1", user_id="u1", result_count=5)
        recent = log.get_recent()
        assert len(recent) == 1
        assert recent[0]["question"] == "test question"
        assert recent[0]["user_id"] == "u1"

    def test_max_entries_eviction(self) -> None:
        log = QueryAuditLog(max_entries=3)
        for i in range(5):
            log.record(f"q{i}", f"sql{i}")
        assert len(log.get_recent(limit=100)) == 3

    def test_stats_empty(self) -> None:
        log = QueryAuditLog()
        stats = log.get_stats()
        assert stats["total_queries"] == 0
        assert stats["cache_hit_rate"] == 0.0

    def test_stats_with_data(self) -> None:
        log = QueryAuditLog()
        log.record("q1", "s1", cache_hit=True, duration_ms=10)
        log.record("q2", "s2", cache_hit=False, duration_ms=20)
        stats = log.get_stats()
        assert stats["total_queries"] == 2
        assert stats["cache_hit_rate"] == 0.5
        assert stats["avg_duration_ms"] == 15.0


class TestExportCSV:
    def test_export_rows(self) -> None:
        rows = [{"name": "a", "value": 1}, {"name": "b", "value": 2}]
        csv_str = export_to_csv(rows)
        assert "name,value" in csv_str
        assert "a,1" in csv_str

    def test_empty_rows(self) -> None:
        assert export_to_csv([]) == ""


class TestExportJSON:
    def test_export_rows(self) -> None:
        rows = [{"name": "a"}]
        result = export_to_json(rows)
        assert '"name": "a"' in result

    def test_compact_mode(self) -> None:
        rows = [{"a": 1}]
        result = export_to_json(rows, pretty=False)
        assert "\n" not in result


class TestExportMarkdown:
    def test_export_table(self) -> None:
        rows = [{"severity": "high", "count": 5}]
        md = export_to_markdown("test query", rows)
        assert "| severity | count |" in md
        assert "| high | 5 |" in md
        assert "**Query:** test query" in md

    def test_empty_results(self) -> None:
        md = export_to_markdown("test", [])
        assert "No results" in md

    def test_truncates_long_values(self) -> None:
        rows = [{"data": "x" * 100}]
        md = export_to_markdown("test", rows)
        # Values truncated to 50 chars
        lines = md.split("\n")
        data_line = [line for line in lines if "xxx" in line][0]
        assert len(data_line) < 200


class TestQueryTemplates:
    def test_templates_exist(self) -> None:
        assert "daily_threat_briefing" in QUERY_TEMPLATES
        assert "weekly_compliance_summary" in QUERY_TEMPLATES
        assert "monthly_executive_report" in QUERY_TEMPLATES

    def test_template_has_required_fields(self) -> None:
        for name, template in QUERY_TEMPLATES.items():
            assert "name" in template, f"{name} missing 'name'"
            assert "sql" in template, f"{name} missing 'sql'"
            assert "SELECT" in template["sql"].upper(), f"{name} SQL doesn't start with SELECT"
