"""LangGraph node implementations for the Natural Language Query agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.nl_query.models import OutputFormat, QueryStage, QueryType
from shieldops.agents.nl_query.tools import (
    NLQueryToolkit,
    SQLValidationError,
    validate_sql,
)

logger = structlog.get_logger()


async def parse_question(state: dict[str, Any], toolkit: NLQueryToolkit) -> dict[str, Any]:
    """Extract intent signals from the raw question."""
    question = state.get("question", "").strip()
    q_lower = question.lower()

    # time-range heuristic
    time_range = state.get("time_range") or ""
    if not time_range:
        if "week" in q_lower or "7 day" in q_lower:
            time_range = "7d"
        elif "month" in q_lower or "30 day" in q_lower:
            time_range = "30d"
        elif "hour" in q_lower:
            time_range = "1h"
        else:
            time_range = "24h"

    intent: dict[str, Any] = {
        "question": question,
        "time_range": time_range,
        "is_count": any(w in q_lower for w in ("how many", "count", "total", "number of")),
        "is_top": any(w in q_lower for w in ("top", "most", "highest", "worst")),
        "is_trend": any(w in q_lower for w in ("trend", "over time", "by day", "per day")),
    }

    logger.info("nl_query.parse", question=question[:100], time_range=time_range)
    return {
        "stage": QueryStage.PARSE,
        "intent": intent,
        "time_range": time_range,
        "reasoning_chain": [*state.get("reasoning_chain", []), "parsed question"],
    }


async def generate_sql(state: dict[str, Any], toolkit: NLQueryToolkit) -> dict[str, Any]:
    """Generate SQL via LLM with heuristic fallback."""
    question = state.get("question", "")
    try:
        sql, query_type, source = await toolkit.generate_sql(question)
    except Exception as exc:
        logger.error("nl_query.generate_sql_failed", error=str(exc))
        return {
            "stage": QueryStage.FAILED,
            "error": f"SQL generation failed: {exc}",
        }

    logger.info("nl_query.generate_sql", source=source, type=query_type.value)
    return {
        "stage": QueryStage.GENERATE_SQL,
        "sql": sql,
        "sql_source": source,
        "query_type": query_type,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"generated SQL via {source}",
        ],
    }


async def validate_sql_node(
    state: dict[str, Any],
    toolkit: NLQueryToolkit,
) -> dict[str, Any]:
    """Validate the generated SQL for safety."""
    sql = state.get("sql", "")
    try:
        validate_sql(sql)
    except SQLValidationError as exc:
        logger.warning("nl_query.sql_rejected", reason=str(exc), sql=sql[:200])
        return {
            "stage": QueryStage.FAILED,
            "validated": False,
            "error": f"SQL rejected: {exc}",
        }

    return {
        "stage": QueryStage.VALIDATE_SQL,
        "validated": True,
        "reasoning_chain": [*state.get("reasoning_chain", []), "validated SQL"],
    }


async def execute(state: dict[str, Any], toolkit: NLQueryToolkit) -> dict[str, Any]:
    """Execute the validated SQL against the EventStore."""
    if not state.get("validated"):
        return {"stage": QueryStage.FAILED, "error": "SQL not validated"}

    sql = state.get("sql", "")
    org_id = state.get("org_id", "")

    try:
        rows = await toolkit.execute_query(sql, {}, org_id=org_id)
    except Exception as exc:
        logger.error("nl_query.execute_failed", error=str(exc))
        return {
            "stage": QueryStage.FAILED,
            "error": f"Query execution failed: {exc}",
        }

    logger.info("nl_query.executed", rows=len(rows))
    return {
        "stage": QueryStage.EXECUTE,
        "results": rows,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"executed ({len(rows)} rows)",
        ],
    }


async def format_output(
    state: dict[str, Any],
    toolkit: NLQueryToolkit,
) -> dict[str, Any]:
    """Format results into markdown + summary."""
    results = state.get("results", [])
    query_type_raw = state.get("query_type", QueryType.UNKNOWN)
    query_type = (
        query_type_raw if isinstance(query_type_raw, QueryType) else QueryType(str(query_type_raw))
    )
    question = state.get("question", "")

    start = time.monotonic()
    markdown, summary, fmt = toolkit.format_results(results, query_type, question)
    duration_ms = int((time.monotonic() - start) * 1000)

    return {
        "stage": QueryStage.COMPLETE,
        "markdown": markdown,
        "summary": summary,
        "output_format": fmt,
        "duration_ms": state.get("duration_ms", 0) + duration_ms,
        "reasoning_chain": [*state.get("reasoning_chain", []), "formatted output"],
    }


async def handle_error(state: dict[str, Any], toolkit: NLQueryToolkit) -> dict[str, Any]:
    """Terminal node — surface the error in human-readable form."""
    error = state.get("error", "Unknown error")
    return {
        "stage": QueryStage.FAILED,
        "markdown": f"**Error:** {error}",
        "summary": error,
        "output_format": OutputFormat.ERROR,
    }
