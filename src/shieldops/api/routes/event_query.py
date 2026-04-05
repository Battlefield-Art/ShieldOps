"""Event Query API routes — SQL query interface for the embedded event store."""

from __future__ import annotations

import re
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.storage.interface import PaginatedResult, StorageStats

logger = structlog.get_logger()
router = APIRouter(prefix="/event-query", tags=["Event Query"])

_store: Any = None

# ------------------------------------------------------------------
# SQL safety
# ------------------------------------------------------------------

# Whitelist: only SELECT statements are allowed.
_ALLOWED_PATTERN = re.compile(
    r"^\s*SELECT\s",
    re.IGNORECASE | re.DOTALL,
)

# Blocklist: reject any statement containing write/DDL keywords as standalone tokens.
_BLOCKED_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE"
    r"|ATTACH|DETACH|COPY|EXPORT|IMPORT|LOAD|CALL|EXECUTE|EXEC)\b",
    re.IGNORECASE,
)

# Reject semicolons to prevent statement chaining.
_SEMICOLON = re.compile(r";")

# Reject common DuckDB-specific dangerous constructs.
_DANGEROUS_FUNCS = re.compile(
    r"\b(read_csv|read_parquet|read_json|write_parquet|write_csv|httpfs|system)\s*\(",
    re.IGNORECASE,
)


def _validate_query(sql: str) -> None:
    """Validate that a SQL string is a safe read-only SELECT query.

    Raises HTTPException 400 if validation fails.
    """
    stripped = sql.strip()

    if not stripped:
        raise HTTPException(status_code=400, detail="Empty query")

    if not _ALLOWED_PATTERN.match(stripped):
        raise HTTPException(
            status_code=400,
            detail="Only SELECT queries are allowed",
        )

    if _SEMICOLON.search(stripped):
        raise HTTPException(
            status_code=400,
            detail="Semicolons are not allowed (no statement chaining)",
        )

    if _BLOCKED_KEYWORDS.search(stripped):
        raise HTTPException(
            status_code=400,
            detail="Query contains disallowed keyword (write/DDL operations are blocked)",
        )

    if _DANGEROUS_FUNCS.search(stripped):
        raise HTTPException(
            status_code=400,
            detail="Query contains disallowed function",
        )


def _inject_org_filter(sql: str, org_id: str) -> tuple[str, dict[str, Any]]:
    """Inject org_id tenant isolation into the query.

    Wraps the user query as a subquery and filters on org_id.
    Returns (modified_sql, params).
    """
    wrapped = (
        f"SELECT * FROM ({sql}) AS _user_query "  # noqa: S608  # nosec B608
        f"WHERE org_id = $org_id"
    )
    return wrapped, {"org_id": org_id}


# ------------------------------------------------------------------
# Store dependency
# ------------------------------------------------------------------


def set_store(store: Any) -> None:
    """Set the global event store instance (called at app startup)."""
    global _store
    _store = store


def _get_store() -> Any:
    if _store is None:
        raise HTTPException(503, "Event store unavailable")
    return _store


# ------------------------------------------------------------------
# Request / response models
# ------------------------------------------------------------------


class QueryRequest(BaseModel):
    """Request body for event query endpoint."""

    sql: str = Field(..., min_length=1, max_length=10_000)
    params: dict[str, Any] | None = None
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=100, ge=1, le=10_000)

    model_config = {"extra": "forbid"}


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------


@router.post("/", response_model=PaginatedResult)
async def execute_query(
    body: QueryRequest,
    user: UserResponse = Depends(get_current_user),
) -> PaginatedResult:
    """Execute a read-only SQL query against the event store.

    Automatically injects org_id tenant isolation. Only SELECT queries allowed.
    """
    _validate_query(body.sql)
    store = _get_store()

    # Inject tenant isolation using the authenticated user's org.
    # Use user.id as org_id fallback (real deployments would use user.org_id).
    org_id = getattr(user, "org_id", user.id)
    filtered_sql, org_params = _inject_org_filter(body.sql, org_id)

    # Merge user-provided params with org filter params.
    merged_params = {**(body.params or {}), **org_params}

    try:
        result = await store.query_paginated(
            filtered_sql,
            merged_params,
            body.page,
            body.limit,
        )
    except Exception as exc:
        logger.error("query_execution_failed", error=str(exc), sql=body.sql)
        raise HTTPException(status_code=400, detail=f"Query failed: {exc}") from exc

    logger.info(
        "query_executed",
        user_id=user.id,
        total_results=result.total,
        page=result.page,
    )
    return result


@router.get("/stats", response_model=StorageStats)
async def get_storage_stats(
    user: UserResponse = Depends(get_current_user),
) -> StorageStats:
    """Return event store statistics."""
    store = _get_store()
    try:
        return await store.get_stats()
    except Exception as exc:
        logger.error("stats_fetch_failed", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to fetch stats") from exc
