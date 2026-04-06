"""Natural language query agent toolkit.

Takes English questions about security events, generates SQL, validates it,
executes against the columnar EventStore, and formats results.
"""

from __future__ import annotations

import re
from typing import Any, cast

import structlog

from shieldops.agents.nl_query.models import OutputFormat, QueryType
from shieldops.agents.nl_query.prompts import (
    SQL_GENERATION_PROMPT,
    SQLGenerationOutput,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# SQL safety — whitelists and blocklists
# ---------------------------------------------------------------------------

ALLOWED_TABLES = frozenset({"events"})

# Statements that mutate data or schema — always rejected.
BLOCKED_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE"
    r"|ATTACH|DETACH|COPY|EXPORT|IMPORT|LOAD|CALL|EXECUTE|EXEC|PRAGMA|VACUUM)\b",
    re.IGNORECASE,
)

# Dangerous file/system functions — always rejected.
DANGEROUS_FUNCS = re.compile(
    r"\b(read_csv|read_parquet|read_json|write_parquet|write_csv|httpfs|system|"
    r"shell_exec|load_extension|install)\s*\(",
    re.IGNORECASE,
)

# Only SELECT statements allowed.
SELECT_PATTERN = re.compile(r"^\s*SELECT\s", re.IGNORECASE | re.DOTALL)

# No statement chaining.
SEMICOLON_PATTERN = re.compile(r";\s*\S")

# Cap on results returned (defense-in-depth vs LIMIT in SQL).
MAX_ROWS = 10_000


# ---------------------------------------------------------------------------
# Heuristic templates for common query patterns
# ---------------------------------------------------------------------------

HEURISTIC_TEMPLATES: list[tuple[re.Pattern[str], str, QueryType]] = [
    (
        re.compile(r"\b(count|how many|total|number of).*event", re.IGNORECASE),
        "SELECT COUNT(*) AS event_count FROM events WHERE org_id = :org_id LIMIT 1",
        QueryType.COUNT,
    ),
    (
        re.compile(r"\b(top|most|highest)\b.*\b(source|provider)", re.IGNORECASE),
        (
            "SELECT source_provider, COUNT(*) AS cnt FROM events "
            "WHERE org_id = :org_id GROUP BY source_provider "
            "ORDER BY cnt DESC LIMIT 10"
        ),
        QueryType.AGGREGATION,
    ),
    (
        re.compile(r"\b(by|per|group).*(type|event_type)", re.IGNORECASE),
        (
            "SELECT event_type, COUNT(*) AS cnt FROM events "
            "WHERE org_id = :org_id GROUP BY event_type "
            "ORDER BY cnt DESC LIMIT 100"
        ),
        QueryType.AGGREGATION,
    ),
    (
        re.compile(r"\b(by|per|group).*severity", re.IGNORECASE),
        (
            "SELECT severity, COUNT(*) AS cnt FROM events "
            "WHERE org_id = :org_id GROUP BY severity ORDER BY cnt DESC LIMIT 10"
        ),
        QueryType.AGGREGATION,
    ),
    (
        re.compile(r"\b(critical|high severity)", re.IGNORECASE),
        (
            "SELECT * FROM events WHERE org_id = :org_id "
            "AND severity IN ('critical','high') "
            "ORDER BY timestamp DESC LIMIT 100"
        ),
        QueryType.TABULAR,
    ),
    (
        re.compile(r"\b(trend|over time|by day|daily|per day)", re.IGNORECASE),
        (
            "SELECT DATE_TRUNC('day', timestamp) AS day, COUNT(*) AS cnt "
            "FROM events WHERE org_id = :org_id "
            "GROUP BY day ORDER BY day DESC LIMIT 90"
        ),
        QueryType.TIME_SERIES,
    ),
    (
        re.compile(r"\b(show|list|recent|latest).*event", re.IGNORECASE),
        (
            "SELECT event_id, timestamp, event_type, severity, source_provider "
            "FROM events WHERE org_id = :org_id ORDER BY timestamp DESC LIMIT 100"
        ),
        QueryType.TABULAR,
    ),
]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


class SQLValidationError(ValueError):
    """Raised when generated SQL fails safety validation."""


def validate_sql(sql: str) -> None:
    """Validate SQL is a safe read-only SELECT against allowed tables.

    Raises SQLValidationError on any violation.
    """
    stripped = sql.strip().rstrip(";").strip()
    if not stripped:
        raise SQLValidationError("Empty SQL")

    if not SELECT_PATTERN.match(stripped):
        raise SQLValidationError("Only SELECT statements are permitted")

    if BLOCKED_KEYWORDS.search(stripped):
        raise SQLValidationError("Blocked SQL keyword detected")

    if DANGEROUS_FUNCS.search(stripped):
        raise SQLValidationError("Dangerous function call detected")

    if SEMICOLON_PATTERN.search(stripped):
        raise SQLValidationError("Statement chaining is not permitted")

    # Table whitelist — look for FROM / JOIN targets.
    tables = re.findall(
        r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)",
        stripped,
        flags=re.IGNORECASE,
    )
    for table in tables:
        if table.lower() not in ALLOWED_TABLES:
            raise SQLValidationError(f"Table '{table}' is not in the allow-list")


def enforce_org_filter(sql: str, org_id: str) -> tuple[str, dict[str, Any]]:
    """Ensure the query filters by ``org_id`` for tenant isolation.

    Wraps the user SQL in an outer SELECT that enforces the org filter and
    caps results at ``MAX_ROWS``. Returns ``(sql, params)``.
    """
    stripped = sql.strip().rstrip(";").strip()
    wrapped = (
        f"SELECT * FROM ({stripped}) AS _inner "  # noqa: S608  # nosec B608
        f"WHERE _inner.org_id = :org_id "
        f"LIMIT {MAX_ROWS}"
    )
    # If the inner query doesn't SELECT org_id, we still filter via the
    # events-level join; fallback: apply a direct check.
    if re.search(r"\bSELECT\s+\*\s+FROM\s+events\b", stripped, re.IGNORECASE):
        # simple case — rewrite to inject WHERE
        wrapped = _inject_where(stripped, org_id)
    return wrapped, {"org_id": org_id}


def _inject_where(sql: str, org_id: str) -> str:
    """Inject `org_id = :org_id` into the WHERE clause of a simple SELECT."""
    if re.search(r"\bWHERE\b", sql, re.IGNORECASE):
        # Add org_id as first condition
        return re.sub(
            r"\bWHERE\b",
            "WHERE org_id = :org_id AND",
            sql,
            count=1,
            flags=re.IGNORECASE,
        )
    # Insert WHERE before ORDER BY / GROUP BY / LIMIT if present.
    insert_re = re.compile(r"\b(ORDER BY|GROUP BY|LIMIT)\b", re.IGNORECASE)
    m = insert_re.search(sql)
    if m:
        idx = m.start()
        return sql[:idx] + "WHERE org_id = :org_id " + sql[idx:]
    return sql + " WHERE org_id = :org_id"


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class NLQueryToolkit:
    """Toolkit: question → SQL → execution → formatted results."""

    def __init__(self, storage: Any = None) -> None:
        self._storage = storage
        self._history: list[dict[str, Any]] = []

    # --- SQL generation ------------------------------------------------

    async def generate_sql(
        self,
        question: str,
        schema_hint: str | None = None,
    ) -> tuple[str, QueryType, str]:
        """Generate SQL from a natural language question.

        Tries the LLM first; falls back to heuristic templates on failure.
        Returns ``(sql, query_type, source)``.
        """
        # Try LLM first
        try:
            from shieldops.utils.llm import llm_structured

            prompt = SQL_GENERATION_PROMPT
            if schema_hint:
                prompt = f"{prompt}\n\nExtra schema context:\n{schema_hint}"

            result = cast(
                SQLGenerationOutput,
                await llm_structured(
                    system_prompt=prompt,
                    user_prompt=question,
                    schema=SQLGenerationOutput,
                ),
            )
            sql = result.sql.strip()
            qtype = _parse_query_type(result.query_type)
            # Validate before returning.
            validate_sql(sql)
            return sql, qtype, "llm"
        except Exception as exc:
            logger.debug("nl_query.llm_fallback", error=str(exc))

        # Heuristic fallback
        sql, qtype = self._heuristic_sql(question)
        return sql, qtype, "heuristic"

    def _heuristic_sql(self, question: str) -> tuple[str, QueryType]:
        """Pattern-match a question against heuristic templates."""
        for pattern, template, qtype in HEURISTIC_TEMPLATES:
            if pattern.search(question):
                return template, qtype
        # Default: recent events for this org.
        return (
            (
                "SELECT event_id, timestamp, event_type, severity, source_provider "
                "FROM events WHERE org_id = :org_id "
                "ORDER BY timestamp DESC LIMIT 100"
            ),
            QueryType.TABULAR,
        )

    # --- Execution -----------------------------------------------------

    async def execute_query(
        self,
        sql: str,
        params: dict[str, Any],
        org_id: str,
    ) -> list[dict[str, Any]]:
        """Execute SQL via the injected EventStore with tenant isolation."""
        if self._storage is None:
            raise RuntimeError("No storage backend configured")

        # Re-validate before exec (belt-and-braces).
        validate_sql(sql)

        # Always inject org_id param.
        safe_params = dict(params or {})
        safe_params.setdefault("org_id", org_id)

        # If SQL references :org_id and doesn't yet have it in WHERE, we trust
        # the caller to have produced an org-filtered query; otherwise inject.
        if ":org_id" not in sql and "org_id" not in sql.lower():
            sql = _inject_where(sql, org_id)

        rows = await self._storage.query(sql, safe_params)
        if len(rows) > MAX_ROWS:
            rows = rows[:MAX_ROWS]

        self._history.append({"sql": sql, "rows": len(rows)})
        return rows

    # --- Formatting ----------------------------------------------------

    def format_results(
        self,
        results: list[dict[str, Any]],
        query_type: QueryType,
        question: str = "",
    ) -> tuple[str, str, OutputFormat]:
        """Format results. Returns ``(markdown, summary, format)``."""
        if not results:
            return (
                "No results found.",
                f"No events matched: {question}" if question else "No results",
                OutputFormat.EMPTY,
            )

        if query_type is QueryType.COUNT:
            # Single count row.
            row = results[0]
            val = next(iter(row.values()), 0)
            summary = f"Found {val} event(s)."
            md = f"**{summary}**"
            return md, summary, OutputFormat.SUMMARY

        if query_type is QueryType.AGGREGATION:
            md = _markdown_table(results)
            top = results[0]
            top_key = next(iter(top.keys()))
            top_val = top.get(top_key)
            cnt_key = _find_count_key(top) or "count"
            cnt_val = top.get(cnt_key, "")
            summary = f"Top {top_key}: {top_val} ({cnt_val}). {len(results)} group(s) total."
            return md, summary, OutputFormat.SUMMARY

        if query_type is QueryType.TIME_SERIES:
            md = _markdown_table(results)
            first = results[0]
            last = results[-1]
            cnt_key = _find_count_key(first) or "cnt"
            trend_word = "increasing"
            try:
                if float(last.get(cnt_key, 0)) >= float(first.get(cnt_key, 0)):
                    trend_word = "increasing"
                else:
                    trend_word = "decreasing"
            except (TypeError, ValueError):
                trend_word = "changing"
            summary = (
                f"Time-series of {len(results)} buckets — trend {trend_word} "
                f"from {first.get(cnt_key)} to {last.get(cnt_key)}."
            )
            return md, summary, OutputFormat.TREND

        # Default: tabular
        md = _markdown_table(results)
        summary = f"Returned {len(results)} row(s)."
        return md, summary, OutputFormat.MARKDOWN_TABLE

    def get_history(self) -> list[dict[str, Any]]:
        """Return recent query history (last 50)."""
        return list(self._history[-50:])


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _parse_query_type(raw: str) -> QueryType:
    try:
        return QueryType(raw.lower())
    except ValueError:
        return QueryType.TABULAR


def _find_count_key(row: dict[str, Any]) -> str | None:
    for key in row:
        if key.lower() in {"count", "cnt", "event_count", "total", "n"}:
            return key
    return None


def _markdown_table(rows: list[dict[str, Any]], max_rows: int = 50) -> str:
    """Render a list of dicts as a Markdown table."""
    if not rows:
        return "_No rows_"

    headers = list(rows[0].keys())
    lines = [
        "| " + " | ".join(str(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows[:max_rows]:
        lines.append(
            "| " + " | ".join(_cell(row.get(h)) for h in headers) + " |",
        )
    if len(rows) > max_rows:
        lines.append(f"_...{len(rows) - max_rows} more rows truncated_")
    return "\n".join(lines)


def _cell(value: Any) -> str:
    """Render a cell value for a Markdown table."""
    if value is None:
        return ""
    s = str(value)
    # Escape pipes inside values.
    return s.replace("|", "\\|").replace("\n", " ")
