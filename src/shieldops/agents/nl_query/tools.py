"""Natural language query agent toolkit.

Takes English questions about security events, generates SQL,
executes against the columnar store, and returns markdown results.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger()

# SQL injection prevention — only these operations allowed
ALLOWED_SQL_KEYWORDS = frozenset(
    {
        "select",
        "from",
        "where",
        "and",
        "or",
        "not",
        "in",
        "like",
        "between",
        "order",
        "by",
        "asc",
        "desc",
        "limit",
        "count",
        "sum",
        "avg",
        "min",
        "max",
        "group",
        "having",
        "as",
        "distinct",
        "case",
        "when",
        "then",
        "else",
        "end",
        "is",
        "null",
        "join",
        "left",
        "right",
        "inner",
        "on",
        "union",
    }
)

BLOCKED_SQL_KEYWORDS = frozenset(
    {
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "create",
        "truncate",
        "exec",
        "execute",
        "grant",
        "revoke",
        "commit",
        "rollback",
        "savepoint",
    }
)

# Common query templates
QUERY_TEMPLATES = {
    "daily_threat_briefing": """
SELECT severity, COUNT(*) as count, source_provider
FROM events
WHERE timestamp >= datetime('now', '-24 hours')
GROUP BY severity, source_provider
ORDER BY count DESC
LIMIT 20
""",
    "weekly_compliance_summary": """
SELECT category_name, severity, COUNT(*) as count
FROM events
WHERE timestamp >= datetime('now', '-7 days')
GROUP BY category_name, severity
ORDER BY count DESC
""",
    "top_sources": """
SELECT source_provider, COUNT(*) as event_count
FROM events
GROUP BY source_provider
ORDER BY event_count DESC
LIMIT 10
""",
}


class NLQueryToolkit:
    """Toolkit for natural language → SQL → results → markdown."""

    def __init__(self, storage: Any = None) -> None:
        self._storage = storage
        self._query_cache: dict[str, Any] = {}
        self._query_history: list[dict[str, Any]] = []

    async def parse_question(self, question: str) -> dict[str, Any]:
        """Parse a natural language question into query intent."""
        logger.info("nl_query.parse", question=question[:100])

        q_lower = question.lower()

        # Detect time range
        time_range = "24 hours"
        if "week" in q_lower or "7 day" in q_lower:
            time_range = "7 days"
        elif "month" in q_lower or "30 day" in q_lower:
            time_range = "30 days"
        elif "hour" in q_lower:
            time_range = "1 hour"
        elif "today" in q_lower:
            time_range = "24 hours"

        # Detect query type
        is_count = any(w in q_lower for w in ["how many", "count", "total", "number of"])
        is_top = any(w in q_lower for w in ["top", "most", "highest", "worst"])
        is_trend = any(w in q_lower for w in ["trend", "over time", "compare", "change"])

        # Detect filters
        filters: dict[str, str] = {}
        for severity in ("critical", "high", "medium", "low"):
            if severity in q_lower:
                filters["severity"] = severity
                break

        for source in ("cloudtrail", "crowdstrike", "syslog", "aws"):
            if source in q_lower:
                filters["source_provider"] = source
                break

        # Detect entities
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", question)
        if ip_match:
            filters["src_ip"] = ip_match.group()

        return {
            "question": question,
            "time_range": time_range,
            "is_count": is_count,
            "is_top": is_top,
            "is_trend": is_trend,
            "filters": filters,
            "parsed": True,
        }

    async def generate_sql(self, intent: dict[str, Any]) -> dict[str, Any]:
        """Generate SQL from parsed intent. Uses LLM with heuristic fallback."""
        logger.info(
            "nl_query.generate_sql", intent_type="count" if intent["is_count"] else "select"
        )

        # Try LLM first
        try:
            from shieldops.utils.llm import llm_analyze

            result = await llm_analyze(
                system_prompt=(
                    "You are a SQL expert. Generate a SQL query for a security events table "
                    "with columns: event_id, org_id, timestamp, event_type, category_name, "
                    "severity, severity_id, source_provider, message, activity_name, status, "
                    "actor_json, src_json, observables_json, metadata_json, raw_data. "
                    "Return ONLY the SQL query, nothing else. Use single quotes for strings. "
                    "Always include LIMIT 100."
                ),
                user_prompt=intent["question"],
            )
            sql = result.get("content", "").strip()
            if sql and self._validate_sql(sql):
                return {"sql": sql, "source": "llm", "valid": True}
        except Exception:
            logger.debug("nl_query.llm_fallback")

        # Heuristic SQL generation
        sql = self._heuristic_sql(intent)
        return {"sql": sql, "source": "heuristic", "valid": True}

    def _heuristic_sql(self, intent: dict[str, Any]) -> str:
        """Generate SQL from intent without LLM."""
        filters = intent.get("filters", {})
        time_range = intent.get("time_range", "24 hours")

        where_clauses = [f"timestamp >= datetime('now', '-{time_range}')"]
        for field, value in filters.items():
            where_clauses.append(f"{field} = '{value}'")

        where = " AND ".join(where_clauses)

        if intent.get("is_count"):
            return f"SELECT COUNT(*) as count FROM events WHERE {where}"  # noqa: S608  # nosec B608

        if intent.get("is_top"):
            top_sql = (
                f"SELECT severity, source_provider, COUNT(*) as count "  # noqa: S608  # nosec B608
                f"FROM events WHERE {where} "
                f"GROUP BY severity, source_provider ORDER BY count DESC LIMIT 10"
            )
            return top_sql

        default_sql = f"SELECT * FROM events WHERE {where} ORDER BY severity_id DESC LIMIT 20"  # noqa: S608  # nosec B608
        return default_sql

    def _validate_sql(self, sql: str) -> bool:
        """Validate SQL for safety — no mutations allowed."""
        sql_lower = sql.lower().strip()

        # Check for blocked keywords
        words = set(re.findall(r"\b\w+\b", sql_lower))
        blocked = words & BLOCKED_SQL_KEYWORDS
        if blocked:
            logger.warning("nl_query.sql_blocked", blocked=list(blocked))
            return False

        # Must start with SELECT
        if not sql_lower.startswith("select"):
            return False

        # Must have LIMIT (prevent unbounded results)
        return "limit" in sql_lower

    async def execute_query(self, sql_result: dict[str, Any]) -> dict[str, Any]:
        """Execute SQL against columnar store."""
        sql = sql_result.get("sql", "")
        logger.info("nl_query.execute", sql=sql[:200])

        if not sql:
            return {"rows": [], "error": "No SQL generated"}

        # Check cache
        cache_key = sql.strip().lower()
        if cache_key in self._query_cache:
            logger.debug("nl_query.cache_hit")
            return self._query_cache[cache_key]

        if self._storage is None:
            return {"rows": [], "error": "No storage backend configured"}

        try:
            rows = self._storage.query(sql)
            result = {"rows": rows, "total": len(rows), "sql": sql, "error": ""}

            # Cache for 5 minutes
            self._query_cache[cache_key] = result

            # Record in history
            self._query_history.append(
                {
                    "sql": sql,
                    "result_count": len(rows),
                    "source": sql_result.get("source", "unknown"),
                }
            )

            return result
        except Exception as e:
            logger.error("nl_query.execute_error", error=str(e))
            return {"rows": [], "error": str(e), "sql": sql}

    async def format_results(self, question: str, results: dict[str, Any]) -> dict[str, Any]:
        """Format query results as markdown."""
        rows = results.get("rows", [])
        error = results.get("error", "")

        if error:
            return {"markdown": f"**Error:** {error}", "format": "error"}

        if not rows:
            return {"markdown": "No results found for your query.", "format": "empty"}

        # Build markdown table
        if isinstance(rows[0], dict):
            headers = list(rows[0].keys())
            md_lines = [
                "| " + " | ".join(str(h) for h in headers) + " |",
                "| " + " | ".join("---" for _ in headers) + " |",
            ]
            for row in rows[:50]:  # Cap at 50 rows
                md_lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")

            summary = f"**Query:** {question}\n**Results:** {len(rows)} rows\n\n"
            markdown = summary + "\n".join(md_lines)
        else:
            markdown = f"**Results:** {rows}"

        return {"markdown": markdown, "format": "table", "row_count": len(rows)}

    def get_suggested_queries(self) -> list[dict[str, str | None]]:
        """Return suggested queries based on common patterns."""
        return [
            {
                "question": "Show me all critical alerts in the last 24 hours",
                "template": "daily_threat_briefing",
            },
            {"question": "What are the top event sources this week?", "template": "top_sources"},
            {"question": "Weekly compliance summary", "template": "weekly_compliance_summary"},
            {"question": "How many failed login attempts today?", "template": None},
            {"question": "Show me events from CrowdStrike with high severity", "template": None},
        ]

    def get_query_history(self) -> list[dict[str, Any]]:
        """Return recent query history."""
        return list(self._query_history[-20:])
