"""Async repository for NL Query audit trail (#5).

Replaces the in-memory ring buffer in :mod:`shieldops.agents.nl_query.audit`
with Postgres-backed persistence.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shieldops.db.models_nl_query_audit import NLQueryAuditRecord

logger = structlog.get_logger(__name__)


class NLQueryAuditRepository:
    """Append-only repository for NL query execution audit records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
    ) -> NLQueryAuditRecord:
        """Persist a single query execution."""
        record = NLQueryAuditRecord(
            org_id=org_id,
            user_id=user_id,
            question=question,
            generated_sql=generated_sql,
            result_count=result_count,
            latency_ms=latency_ms,
            cache_hit=cache_hit,
            source=source,
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        logger.info(
            "nl_query.audit.persisted",
            org_id=org_id,
            source=source,
            rows=result_count,
            latency_ms=latency_ms,
        )
        return record

    async def list_queries(
        self, org_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[NLQueryAuditRecord], int]:
        """Return paginated audit records scoped to ``org_id``, newest first."""
        base = select(NLQueryAuditRecord).where(NLQueryAuditRecord.org_id == org_id)
        count_stmt = select(NLQueryAuditRecord).where(NLQueryAuditRecord.org_id == org_id)
        all_rows = (await self._session.execute(count_stmt)).scalars().all()
        total = len(all_rows)
        stmt = base.order_by(NLQueryAuditRecord.created_at.desc()).offset(offset).limit(limit)
        rows = list((await self._session.execute(stmt)).scalars().all())
        return rows, total
