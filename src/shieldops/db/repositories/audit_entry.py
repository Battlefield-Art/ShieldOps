"""Repository for immutable audit trail — APPEND-ONLY."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models_agent_run import AuditEntry

logger = structlog.get_logger()


class AuditEntryRepository:
    """Async append-only repository for AuditEntry records.

    This repository intentionally exposes NO update or delete methods.
    Audit entries are immutable once written.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def create_entry(
        self,
        action: str,
        actor: str,
        target: str,
        result: str,
        org_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a new audit entry. This is the only write operation."""
        async with self._sf() as session:
            record = AuditEntry(
                action=action,
                actor=actor,
                target=target,
                result=result,
                org_id=org_id,
                metadata_=metadata or {},
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info(
                "audit_entry_created",
                entry_id=record.id,
                action=action,
                actor=actor,
                result=result,
            )
            return record

    async def list_entries(
        self,
        org_id: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        result: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        page: int = 1,
        limit: int = 50,
    ) -> tuple[list[AuditEntry], int]:
        """List audit entries with filters.

        Returns a tuple of (entries, total_count) for pagination.
        """
        async with self._sf() as session:
            stmt = select(AuditEntry).order_by(AuditEntry.created_at.desc())
            count_stmt = select(func.count()).select_from(AuditEntry)

            if org_id:
                stmt = stmt.where(AuditEntry.org_id == org_id)
                count_stmt = count_stmt.where(AuditEntry.org_id == org_id)
            if action:
                stmt = stmt.where(AuditEntry.action == action)
                count_stmt = count_stmt.where(AuditEntry.action == action)
            if actor:
                stmt = stmt.where(AuditEntry.actor == actor)
                count_stmt = count_stmt.where(AuditEntry.actor == actor)
            if result:
                stmt = stmt.where(AuditEntry.result == result)
                count_stmt = count_stmt.where(AuditEntry.result == result)
            if start_date:
                stmt = stmt.where(AuditEntry.created_at >= start_date)
                count_stmt = count_stmt.where(AuditEntry.created_at >= start_date)
            if end_date:
                stmt = stmt.where(AuditEntry.created_at <= end_date)
                count_stmt = count_stmt.where(AuditEntry.created_at <= end_date)

            offset = (page - 1) * limit
            stmt = stmt.offset(offset).limit(limit)

            result_set = await session.execute(stmt)
            entries = list(result_set.scalars().all())

            count_result = await session.execute(count_stmt)
            total = count_result.scalar_one()

            return entries, total
