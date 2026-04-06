"""Unit tests for the Natural Language Query agent."""

from __future__ import annotations

from typing import Any

import pytest

from shieldops.agents.nl_query import (
    NLQueryRequest,
    NLQueryRunner,
    NLQueryToolkit,
    OutputFormat,
    QueryType,
    SQLValidationError,
    validate_sql,
)
from shieldops.agents.nl_query.tools import _inject_where

# ---------------------------------------------------------------------------
# Fake storage backend
# ---------------------------------------------------------------------------


class FakeStorage:
    """In-memory stand-in for the EventStore protocol."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self._rows = rows or []
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        self.calls.append((sql, params))
        # If caller supplies org_id filter, apply it.
        org_id = (params or {}).get("org_id")
        if org_id is not None:
            return [r for r in self._rows if r.get("org_id") == org_id]
        return list(self._rows)


# ---------------------------------------------------------------------------
# validate_sql
# ---------------------------------------------------------------------------


class TestValidateSQL:
    def test_select_is_allowed(self) -> None:
        validate_sql("SELECT * FROM events LIMIT 10")

    def test_drop_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("DROP TABLE events")

    def test_delete_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("DELETE FROM events WHERE 1=1")

    def test_update_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("UPDATE events SET severity='low'")

    def test_insert_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("INSERT INTO events VALUES (1)")

    def test_alter_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("ALTER TABLE events ADD COLUMN foo VARCHAR")

    def test_create_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("CREATE TABLE foo(x INT)")

    def test_attach_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("ATTACH 'other.db' AS other")

    def test_copy_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("COPY events TO 'out.csv'")

    def test_read_parquet_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("SELECT * FROM read_parquet('x.parquet')")

    def test_read_csv_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("SELECT * FROM read_csv('x.csv')")

    def test_non_whitelisted_table_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("SELECT * FROM secrets LIMIT 10")

    def test_statement_chaining_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("SELECT * FROM events; DROP TABLE events")

    def test_empty_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("")

    def test_non_select_rejected(self) -> None:
        with pytest.raises(SQLValidationError):
            validate_sql("PRAGMA tables")


# ---------------------------------------------------------------------------
# Heuristic SQL generation
# ---------------------------------------------------------------------------


class TestHeuristicSQL:
    @pytest.fixture
    def toolkit(self) -> NLQueryToolkit:
        return NLQueryToolkit(storage=FakeStorage())

    def test_count_template(self, toolkit: NLQueryToolkit) -> None:
        sql, qtype = toolkit._heuristic_sql("how many events happened today?")
        assert "COUNT(*)" in sql
        assert qtype is QueryType.COUNT
        assert ":org_id" in sql

    def test_top_sources_template(self, toolkit: NLQueryToolkit) -> None:
        sql, qtype = toolkit._heuristic_sql("top sources this week")
        assert "source_provider" in sql
        assert "GROUP BY" in sql
        assert qtype is QueryType.AGGREGATION

    def test_by_event_type_template(self, toolkit: NLQueryToolkit) -> None:
        sql, qtype = toolkit._heuristic_sql("show events by event_type")
        assert "event_type" in sql
        assert qtype is QueryType.AGGREGATION

    def test_trend_template(self, toolkit: NLQueryToolkit) -> None:
        sql, qtype = toolkit._heuristic_sql("event trend over time")
        assert "DATE_TRUNC" in sql
        assert qtype is QueryType.TIME_SERIES

    def test_default_recent_events(self, toolkit: NLQueryToolkit) -> None:
        sql, qtype = toolkit._heuristic_sql("zzz unknown question")
        assert "SELECT" in sql
        assert "events" in sql
        assert qtype is QueryType.TABULAR


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_execute_injects_org_id_param(self) -> None:
        storage = FakeStorage(
            rows=[
                {"org_id": "org-1", "event_id": "a"},
                {"org_id": "org-2", "event_id": "b"},
            ]
        )
        toolkit = NLQueryToolkit(storage=storage)
        sql = "SELECT * FROM events WHERE org_id = :org_id LIMIT 100"

        rows = await toolkit.execute_query(sql, {}, org_id="org-1")

        assert len(rows) == 1
        assert rows[0]["org_id"] == "org-1"
        # Params must include org_id
        assert storage.calls[-1][1] == {"org_id": "org-1"}

    def test_inject_where_adds_org_id(self) -> None:
        out = _inject_where(
            "SELECT * FROM events WHERE severity='high' LIMIT 10",
            "org-1",
        )
        assert "org_id = :org_id" in out

    def test_inject_where_no_existing_where(self) -> None:
        out = _inject_where(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT 10",
            "org-1",
        )
        assert "WHERE org_id = :org_id" in out


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


class TestFormatResults:
    @pytest.fixture
    def toolkit(self) -> NLQueryToolkit:
        return NLQueryToolkit(storage=FakeStorage())

    def test_empty_results(self, toolkit: NLQueryToolkit) -> None:
        md, summary, fmt = toolkit.format_results([], QueryType.TABULAR, "any?")
        assert fmt is OutputFormat.EMPTY
        assert "No" in md

    def test_count_summary(self, toolkit: NLQueryToolkit) -> None:
        md, summary, fmt = toolkit.format_results(
            [{"event_count": 42}],
            QueryType.COUNT,
            "how many?",
        )
        assert fmt is OutputFormat.SUMMARY
        assert "42" in summary

    def test_aggregation_summary(self, toolkit: NLQueryToolkit) -> None:
        md, summary, fmt = toolkit.format_results(
            [
                {"source_provider": "aws", "count": 100},
                {"source_provider": "gcp", "count": 50},
            ],
            QueryType.AGGREGATION,
            "top sources",
        )
        assert fmt is OutputFormat.SUMMARY
        assert "source_provider" in md
        assert "100" in md
        assert "aws" in summary

    def test_tabular_markdown(self, toolkit: NLQueryToolkit) -> None:
        rows = [
            {"event_id": "e1", "severity": "high"},
            {"event_id": "e2", "severity": "low"},
        ]
        md, summary, fmt = toolkit.format_results(rows, QueryType.TABULAR)
        assert fmt is OutputFormat.MARKDOWN_TABLE
        assert "| event_id | severity |" in md
        assert "e1" in md
        assert "e2" in md

    def test_time_series_trend(self, toolkit: NLQueryToolkit) -> None:
        rows = [
            {"day": "2026-04-01", "cnt": 10},
            {"day": "2026-04-02", "cnt": 20},
            {"day": "2026-04-03", "cnt": 30},
        ]
        md, summary, fmt = toolkit.format_results(rows, QueryType.TIME_SERIES)
        assert fmt is OutputFormat.TREND
        assert "trend" in summary.lower()

    def test_markdown_escapes_pipes(self, toolkit: NLQueryToolkit) -> None:
        md, _, _ = toolkit.format_results(
            [{"x": "a|b"}],
            QueryType.TABULAR,
        )
        assert "a\\|b" in md


# ---------------------------------------------------------------------------
# End-to-end runner with heuristic fallback (no LLM)
# ---------------------------------------------------------------------------


class TestRunnerE2E:
    @pytest.mark.asyncio
    async def test_run_heuristic_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Force LLM to fail so we exercise the heuristic path.
        async def _boom(*a: Any, **kw: Any) -> Any:
            raise RuntimeError("llm unavailable")

        monkeypatch.setattr("shieldops.utils.llm.llm_structured", _boom)

        storage = FakeStorage(
            rows=[
                {"org_id": "org-1", "event_id": "a", "severity": "high"},
                {"org_id": "org-1", "event_id": "b", "severity": "low"},
                {"org_id": "org-2", "event_id": "c", "severity": "high"},
            ]
        )
        runner = NLQueryRunner(storage=storage)

        response = await runner.run(
            NLQueryRequest(question="how many events today"),
            org_id="org-1",
        )

        assert response.error == ""
        assert response.source == "heuristic"
        assert response.sql
        assert "SELECT" in response.sql.upper()
        # Tenant isolated to org-1
        assert all(r.get("org_id") == "org-1" for r in response.results)

    @pytest.mark.asyncio
    async def test_run_rejects_bad_sql_from_llm(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # LLM returns a dangerous statement; toolkit must fall back to heuristic.
        from shieldops.agents.nl_query.prompts import SQLGenerationOutput

        async def _bad(*a: Any, **kw: Any) -> Any:
            return SQLGenerationOutput(
                sql="DROP TABLE events",
                query_type="tabular",
                explanation="",
            )

        monkeypatch.setattr("shieldops.utils.llm.llm_structured", _bad)

        storage = FakeStorage(rows=[{"org_id": "org-1", "event_id": "x"}])
        runner = NLQueryRunner(storage=storage)

        response = await runner.run(
            NLQueryRequest(question="show me events"),
            org_id="org-1",
        )

        # Dangerous LLM SQL must be rejected → falls back to heuristic, succeeds.
        assert response.source == "heuristic"
        assert "DROP" not in response.sql.upper()
        assert response.error == ""

    @pytest.mark.asyncio
    async def test_run_tenant_isolation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*a: Any, **kw: Any) -> Any:
            raise RuntimeError("no llm")

        monkeypatch.setattr("shieldops.utils.llm.llm_structured", _boom)

        storage = FakeStorage(
            rows=[
                {"org_id": "org-A", "event_id": "1"},
                {"org_id": "org-A", "event_id": "2"},
                {"org_id": "org-B", "event_id": "3"},
            ]
        )
        runner = NLQueryRunner(storage=storage)
        response = await runner.run(
            NLQueryRequest(question="show recent events"),
            org_id="org-A",
        )
        assert response.row_count == 2
        assert all(r["org_id"] == "org-A" for r in response.results)
