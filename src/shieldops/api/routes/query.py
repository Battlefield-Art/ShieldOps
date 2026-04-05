"""Natural language query API — English questions → SQL → results."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()
router = APIRouter(prefix="/query", tags=["Natural Language Query"])

# Module-level references (set during app startup)
_toolkit: Any = None
_audit_log: Any = None


def set_query_toolkit(toolkit: Any) -> None:
    global _toolkit
    _toolkit = toolkit


def set_audit_log(audit_log: Any) -> None:
    global _audit_log
    _audit_log = audit_log


class AskRequest(BaseModel):
    question: str
    model_config = {"extra": "forbid"}


class AskResponse(BaseModel):
    markdown: str = ""
    format: str = "empty"
    row_count: int = 0
    sql: str = ""
    cached: bool = False


@router.post("/ask", operation_id="nl_query_ask")
async def ask_question(
    body: AskRequest,
    _user: UserResponse = Depends(get_current_user),
) -> AskResponse:
    """Ask a question in English, get results in markdown."""
    start = time.monotonic()

    if _toolkit is None:
        return AskResponse(
            markdown="**Error:** Query engine not initialized.",
            format="error",
        )

    # Parse → Generate SQL → Execute → Format
    intent = await _toolkit.parse_question(body.question)
    sql_result = await _toolkit.generate_sql(intent)
    results = await _toolkit.execute_query(sql_result)
    formatted = await _toolkit.format_results(body.question, results)

    duration_ms = (time.monotonic() - start) * 1000

    # Audit log
    if _audit_log:
        _audit_log.record(
            question=body.question,
            sql=sql_result.get("sql", ""),
            user_id=_user.id if _user else "",
            result_count=len(results.get("rows", [])),
            duration_ms=duration_ms,
        )

    logger.info(
        "nl_query.ask",
        question=body.question[:100],
        rows=len(results.get("rows", [])),
        duration_ms=round(duration_ms, 1),
    )

    return AskResponse(
        markdown=formatted.get("markdown", ""),
        format=formatted.get("format", "empty"),
        row_count=formatted.get("row_count", 0),
        sql=sql_result.get("sql", ""),
    )


@router.get("/suggestions", operation_id="nl_query_suggestions")
async def get_suggestions(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get suggested queries."""
    if _toolkit is None:
        return {"suggestions": []}
    return {"suggestions": _toolkit.get_suggested_queries()}


@router.get("/history", operation_id="nl_query_history")
async def get_history(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get recent query history."""
    if _toolkit is None:
        return {"history": []}
    return {"history": _toolkit.get_query_history()}


@router.get("/templates", operation_id="nl_query_templates")
async def get_templates(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get pre-built query templates."""
    from shieldops.ingest.query_hardener import QUERY_TEMPLATES

    return {"templates": QUERY_TEMPLATES}
