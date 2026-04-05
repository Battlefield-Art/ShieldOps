"""Tests for natural language query agent toolkit."""

from __future__ import annotations

import pytest

from shieldops.agents.nl_query.tools import NLQueryToolkit
from shieldops.ingest.storage import ColumnarStorage


@pytest.fixture
def storage_with_data() -> ColumnarStorage:
    store = ColumnarStorage()
    store.insert_batch(
        [
            {
                "severity": "critical",
                "severity_id": 5,
                "source_provider": "crowdstrike_fdr",
                "category_name": "security_finding",
                "message": "Ransomware detected",
                "activity_name": "malware",
            },
            {
                "severity": "high",
                "severity_id": 4,
                "source_provider": "aws_cloudtrail",
                "category_name": "api_activity",
                "message": "Unauthorized API call",
                "activity_name": "DeleteBucket",
            },
            {
                "severity": "high",
                "severity_id": 4,
                "source_provider": "crowdstrike_fdr",
                "category_name": "security_finding",
                "message": "Credential dumping",
                "activity_name": "mimikatz",
            },
            {
                "severity": "low",
                "severity_id": 2,
                "source_provider": "syslog",
                "category_name": "system_activity",
                "message": "SSH login success",
                "activity_name": "sshd",
            },
            {
                "severity": "medium",
                "severity_id": 3,
                "source_provider": "aws_cloudtrail",
                "category_name": "authentication",
                "message": "Console login",
                "activity_name": "ConsoleLogin",
            },
        ]
    )
    return store


class TestParseQuestion:
    @pytest.mark.asyncio
    async def test_detects_count_intent(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.parse_question("How many critical alerts today?")
        assert result["is_count"] is True
        assert result["filters"]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_detects_top_intent(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.parse_question("Show me the top sources this week")
        assert result["is_top"] is True
        assert result["time_range"] == "7 days"

    @pytest.mark.asyncio
    async def test_detects_source_filter(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.parse_question("Events from crowdstrike in the last hour")
        assert result["filters"]["source_provider"] == "crowdstrike"
        assert result["time_range"] == "1 hour"

    @pytest.mark.asyncio
    async def test_detects_ip_address(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.parse_question("Show events from 10.0.1.50")
        assert result["filters"]["src_ip"] == "10.0.1.50"

    @pytest.mark.asyncio
    async def test_month_time_range(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.parse_question("Summary for the past month")
        assert result["time_range"] == "30 days"


class TestGenerateSQL:
    @pytest.mark.asyncio
    async def test_count_query(self) -> None:
        toolkit = NLQueryToolkit()
        intent = await toolkit.parse_question("How many events today?")
        result = await toolkit.generate_sql(intent)
        assert "COUNT" in result["sql"].upper()
        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_top_query(self) -> None:
        toolkit = NLQueryToolkit()
        intent = await toolkit.parse_question("Top alerts this week")
        result = await toolkit.generate_sql(intent)
        assert "ORDER BY" in result["sql"].upper()
        assert "DESC" in result["sql"].upper()
        assert "LIMIT" in result["sql"].upper()

    @pytest.mark.asyncio
    async def test_filtered_query(self) -> None:
        toolkit = NLQueryToolkit()
        intent = await toolkit.parse_question("Show critical events from crowdstrike")
        result = await toolkit.generate_sql(intent)
        assert "critical" in result["sql"].lower()


class TestSQLValidation:
    def test_blocks_insert(self) -> None:
        toolkit = NLQueryToolkit()
        assert toolkit._validate_sql("INSERT INTO events VALUES (1)") is False

    def test_blocks_delete(self) -> None:
        toolkit = NLQueryToolkit()
        assert toolkit._validate_sql("DELETE FROM events") is False

    def test_blocks_drop(self) -> None:
        toolkit = NLQueryToolkit()
        assert toolkit._validate_sql("DROP TABLE events") is False

    def test_allows_select(self) -> None:
        toolkit = NLQueryToolkit()
        assert toolkit._validate_sql("SELECT * FROM events LIMIT 10") is True

    def test_requires_limit(self) -> None:
        toolkit = NLQueryToolkit()
        assert toolkit._validate_sql("SELECT * FROM events") is False

    def test_must_start_with_select(self) -> None:
        toolkit = NLQueryToolkit()
        assert toolkit._validate_sql("EXPLAIN SELECT * FROM events LIMIT 10") is False


class TestExecuteQuery:
    @pytest.mark.asyncio
    async def test_returns_rows(self, storage_with_data: ColumnarStorage) -> None:
        toolkit = NLQueryToolkit(storage=storage_with_data)
        result = await toolkit.execute_query({"sql": "SELECT * FROM events LIMIT 5"})
        assert len(result["rows"]) == 5
        assert result["error"] == ""

    @pytest.mark.asyncio
    async def test_filtered_query(self, storage_with_data: ColumnarStorage) -> None:
        toolkit = NLQueryToolkit(storage=storage_with_data)
        result = await toolkit.execute_query(
            {
                "sql": "SELECT * FROM events WHERE severity = 'critical' LIMIT 10",
            }
        )
        assert len(result["rows"]) == 1
        assert result["rows"][0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_no_storage_returns_error(self) -> None:
        toolkit = NLQueryToolkit(storage=None)
        result = await toolkit.execute_query({"sql": "SELECT 1 LIMIT 1"})
        assert result["error"] == "No storage backend configured"

    @pytest.mark.asyncio
    async def test_cache_hit(self, storage_with_data: ColumnarStorage) -> None:
        toolkit = NLQueryToolkit(storage=storage_with_data)
        sql = {"sql": "SELECT * FROM events LIMIT 5"}
        r1 = await toolkit.execute_query(sql)
        r2 = await toolkit.execute_query(sql)
        assert r1["rows"] == r2["rows"]

    @pytest.mark.asyncio
    async def test_query_history_recorded(self, storage_with_data: ColumnarStorage) -> None:
        toolkit = NLQueryToolkit(storage=storage_with_data)
        await toolkit.execute_query({"sql": "SELECT * FROM events LIMIT 1"})
        assert len(toolkit.get_query_history()) == 1


class TestFormatResults:
    @pytest.mark.asyncio
    async def test_markdown_table(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.format_results(
            "test query",
            {
                "rows": [{"severity": "high", "count": 5}, {"severity": "low", "count": 3}],
            },
        )
        assert "| severity | count |" in result["markdown"]
        assert result["format"] == "table"

    @pytest.mark.asyncio
    async def test_empty_results(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.format_results("test", {"rows": []})
        assert "No results" in result["markdown"]
        assert result["format"] == "empty"

    @pytest.mark.asyncio
    async def test_error_format(self) -> None:
        toolkit = NLQueryToolkit()
        result = await toolkit.format_results("test", {"rows": [], "error": "bad query"})
        assert "Error" in result["markdown"]


class TestSuggestedQueries:
    def test_returns_suggestions(self) -> None:
        toolkit = NLQueryToolkit()
        suggestions = toolkit.get_suggested_queries()
        assert len(suggestions) >= 3
        assert all("question" in s for s in suggestions)


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_full_pipeline(self, storage_with_data: ColumnarStorage) -> None:
        toolkit = NLQueryToolkit(storage=storage_with_data)
        intent = await toolkit.parse_question("Show me critical alerts")
        sql = await toolkit.generate_sql(intent)
        results = await toolkit.execute_query(sql)
        formatted = await toolkit.format_results("Show me critical alerts", results)
        assert formatted["format"] in ("table", "empty")
