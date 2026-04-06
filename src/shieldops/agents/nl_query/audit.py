"""NL Query audit trail — persist every query for compliance and debugging."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_AUDIT_LOG: list[dict[str, Any]] = []
_MAX_ENTRIES = 5000


class QueryAuditEntry(BaseModel):
    """A single NL query execution recorded for audit."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str = ""
    user_id: str = ""
    question: str = ""
    generated_sql: str = ""
    result_count: int = 0
    latency_ms: float = 0.0
    cache_hit: bool = False
    source: str = "llm"  # llm | heuristic | cache
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


async def log_query(
    *,
    org_id: str,
    user_id: str,
    question: str,
    generated_sql: str,
    result_count: int,
    latency_ms: float,
    cache_hit: bool = False,
    source: str = "llm",
) -> QueryAuditEntry:
    """Append a query execution to the audit log.

    Ring-buffered in memory for now; production should back this with the
    AuditLog table via :mod:`shieldops.utils.persistence`.
    """
    entry = QueryAuditEntry(
        org_id=org_id,
        user_id=user_id,
        question=question,
        generated_sql=generated_sql,
        result_count=result_count,
        latency_ms=latency_ms,
        cache_hit=cache_hit,
        source=source,
    )
    _AUDIT_LOG.append(entry.model_dump(mode="json"))
    if len(_AUDIT_LOG) > _MAX_ENTRIES:
        _AUDIT_LOG.pop(0)
    logger.info(
        "nl_query.audit",
        org_id=org_id,
        result_count=result_count,
        latency_ms=latency_ms,
        cache_hit=cache_hit,
        source=source,
    )
    return entry


async def list_queries(
    *, org_id: str, limit: int = 50, offset: int = 0
) -> tuple[list[dict[str, Any]], int]:
    """Return paginated audit entries scoped to org_id, newest first."""
    scoped = [e for e in _AUDIT_LOG if e.get("org_id") == org_id]
    scoped.sort(key=lambda e: e.get("created_at", ""), reverse=True)
    total = len(scoped)
    return scoped[offset : offset + limit], total


def clear_audit_log() -> None:
    """Reset the audit log (test helper)."""
    _AUDIT_LOG.clear()
