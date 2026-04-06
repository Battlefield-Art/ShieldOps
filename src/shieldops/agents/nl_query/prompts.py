"""Prompts and structured output schemas for the NL Query agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

EVENTS_SCHEMA_HINT = """\
Table: events
Columns:
  - event_id VARCHAR (primary key)
  - org_id VARCHAR (tenant identifier — filter injected automatically)
  - timestamp TIMESTAMP
  - event_type VARCHAR (e.g. 'login', 'api_call', 'alert')
  - severity VARCHAR (one of 'critical','high','medium','low','info')
  - source_provider VARCHAR (e.g. 'aws','crowdstrike','splunk','wiz')
  - source_type VARCHAR
  - raw_event JSON
  - normalized JSON
  - enrichments JSON
"""

SQL_GENERATION_PROMPT = f"""\
You are a SQL generation assistant for a security event store (DuckDB / ClickHouse compatible).

{EVENTS_SCHEMA_HINT}

Rules:
  1. Output a single SELECT statement only. No INSERT/UPDATE/DELETE/DDL.
  2. Only query the `events` table. No other tables, no CTEs referencing outside tables.
  3. Do NOT include org_id filters in WHERE — the server injects tenant isolation.
  4. Do NOT use read_csv, read_parquet, ATTACH, COPY, or any file/system functions.
  5. Always include a LIMIT clause (default 1000, max 10000).
  6. Use ISO timestamp comparisons for time ranges (e.g. timestamp >= NOW() - INTERVAL '24 hours').
  7. Prefer GROUP BY for "how many" / "count" / "top" / "by X" questions.
  8. For time-series ("over time", "trend", "by day"), use DATE_TRUNC on timestamp.

Return ONLY valid JSON matching the requested schema.
"""


class SQLGenerationOutput(BaseModel):
    """Structured LLM output for SQL generation."""

    sql: str = Field(..., description="The generated SELECT statement.")
    query_type: str = Field(
        default="tabular",
        description="One of: tabular, aggregation, time_series, count.",
    )
    explanation: str = Field(
        default="",
        description="Brief 1-sentence explanation of what the query does.",
    )


SUMMARY_PROMPT = """\
You are a security analyst. Given a natural language question and query results,
write a 1-2 sentence plain-English summary of what the data shows.
Be precise. Include key numbers. Do not hallucinate fields not in the data.
"""


class SummaryOutput(BaseModel):
    """Structured LLM output for result summarization."""

    summary: str = Field(..., description="1-2 sentence summary of the results.")
