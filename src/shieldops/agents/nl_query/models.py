"""Models for the Natural Language Query agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class QueryStage(StrEnum):
    """Stages of the NL query pipeline."""

    PARSE = "parse"
    GENERATE_SQL = "generate_sql"
    VALIDATE_SQL = "validate_sql"
    EXECUTE = "execute"
    FORMAT = "format"
    COMPLETE = "complete"
    FAILED = "failed"


class QueryType(StrEnum):
    """Detected query shape — drives output formatting."""

    TABULAR = "tabular"
    AGGREGATION = "aggregation"
    TIME_SERIES = "time_series"
    COUNT = "count"
    UNKNOWN = "unknown"


class OutputFormat(StrEnum):
    """Output format for the response."""

    MARKDOWN_TABLE = "markdown_table"
    SUMMARY = "summary"
    TREND = "trend"
    EMPTY = "empty"
    ERROR = "error"


class NLQueryRequest(BaseModel):
    """Incoming natural language query request."""

    question: str = Field(..., min_length=1, max_length=1000)
    time_range: str | None = Field(
        default=None,
        description="Optional ISO time range like '24h', '7d', '30d'.",
    )
    max_rows: int = Field(default=1000, ge=1, le=10_000)

    model_config = {"extra": "forbid"}


class NLQueryResponse(BaseModel):
    """Structured response from the NL query agent."""

    question: str
    sql: str = ""
    query_type: QueryType = QueryType.UNKNOWN
    format: OutputFormat = OutputFormat.EMPTY
    results: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
    summary: str = ""
    markdown: str = ""
    source: str = "heuristic"  # "llm" or "heuristic"
    error: str = ""
    duration_ms: int = 0


class NLQueryState(BaseModel):
    """LangGraph state for the NL query agent."""

    request_id: str = ""
    org_id: str = ""
    question: str = ""
    time_range: str = ""
    max_rows: int = 1000

    # pipeline output
    stage: QueryStage = QueryStage.PARSE
    intent: dict[str, Any] = Field(default_factory=dict)
    sql: str = ""
    sql_source: str = "heuristic"
    validated: bool = False
    results: list[dict[str, Any]] = Field(default_factory=list)
    query_type: QueryType = QueryType.UNKNOWN
    output_format: OutputFormat = OutputFormat.EMPTY
    markdown: str = ""
    summary: str = ""

    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
