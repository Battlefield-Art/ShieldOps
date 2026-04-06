"""NL Query audit trail — persistence with optional repository backing.

Two modes:
- **DB-backed** (production): call :func:`set_repository` with an
  :class:`NLQueryAuditRepository`. All log_query/list_queries calls hit the DB.
- **In-memory fallback** (tests/dev): no repository set; a bounded ring
  buffer is used. Capped at 5,000 entries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_AUDIT_LOG: list[dict[str, Any]] = []
_MAX_ENTRIES = 5000


class _AuditRepoProtocol(Protocol):
    async def log_query(
        self,
        *,
        org_id: str,
        user_id: str,
        question: str,
        generated_sql: str,
        result_count: int,
        latency_ms: float,
        cache_hit: bool = False,
        source: str = "llm",
    ) -> Any: ...

    async def list_queries(
        self, org_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[Any], int]: ...


_repository: _AuditRepoProtocol | None = None


def set_repository(repo: _AuditRepoProtocol | None) -> None:
    """Inject a DB-backed audit repository. Pass ``None`` to clear."""
    global _repository
    _repository = repo


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
    """Append a query execution to the audit log (repo or in-memory)."""
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

    if _repository is not None:
        try:
            await _repository.log_query(
                org_id=org_id,
                user_id=user_id,
                question=question,
                generated_sql=generated_sql,
                result_count=result_count,
                latency_ms=latency_ms,
                cache_hit=cache_hit,
                source=source,
            )
            logger.debug("nl_query.audit.persisted_via_repo", org_id=org_id)
            return entry
        except Exception as exc:
            logger.warning(
                "nl_query.audit.repo_failed_falling_back",
                error=str(exc),
                org_id=org_id,
            )

    # In-memory fallback
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
    if _repository is not None:
        try:
            rows, total = await _repository.list_queries(org_id, limit=limit, offset=offset)
            # Normalize records to plain dicts for JSON serialization
            normalized = [_record_to_dict(r) for r in rows]
            return normalized, total
        except Exception as exc:
            logger.warning(
                "nl_query.audit.list_repo_failed_falling_back",
                error=str(exc),
                org_id=org_id,
            )

    scoped = [e for e in _AUDIT_LOG if e.get("org_id") == org_id]
    scoped.sort(key=lambda e: e.get("created_at", ""), reverse=True)
    total = len(scoped)
    return scoped[offset : offset + limit], total


def _record_to_dict(record: Any) -> dict[str, Any]:
    """Convert either an ORM record or a dict to a plain dict."""
    if isinstance(record, dict):
        return record
    fields = (
        "id",
        "org_id",
        "user_id",
        "question",
        "generated_sql",
        "result_count",
        "latency_ms",
        "cache_hit",
        "source",
        "created_at",
    )
    out: dict[str, Any] = {}
    for f in fields:
        if hasattr(record, f):
            val = getattr(record, f)
            if isinstance(val, datetime):
                val = val.isoformat()
            out[f] = val
    return out


def clear_audit_log() -> None:
    """Reset the in-memory audit log (test helper)."""
    _AUDIT_LOG.clear()
