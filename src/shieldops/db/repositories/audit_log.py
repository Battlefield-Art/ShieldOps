"""Unified tenant-aware audit log repository (#6).

Replaces ad-hoc in-memory audit logs scattered across subsystems. Append-only:
no update or delete methods are exposed on the public interface.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shieldops.db.models_audit_log import AuditLogRecord

logger = structlog.get_logger(__name__)


class AuditLogRepository:
    """Append-only audit log repository scoped by ``org_id``."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        org_id: str,
        action: str,
        actor: str = "",
        target: str = "",
        result: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditLogRecord:
        """Persist a single audit entry."""
        record = AuditLogRecord(
            org_id=org_id,
            action=action,
            actor=actor,
            target=target,
            result=result,
            metadata_=metadata or {},
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        logger.debug(
            "audit_log.persisted",
            org_id=org_id,
            action=action,
            actor=actor,
            result=result,
        )
        return record

    async def list_entries(
        self,
        org_id: str,
        *,
        action: str | None = None,
        actor: str | None = None,
        result: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLogRecord], int]:
        """Paginated tenant-scoped listing with optional filters, newest first."""
        conditions = [AuditLogRecord.org_id == org_id]
        if action is not None:
            conditions.append(AuditLogRecord.action == action)
        if actor is not None:
            conditions.append(AuditLogRecord.actor == actor)
        if result is not None:
            conditions.append(AuditLogRecord.result == result)
        if since is not None:
            conditions.append(AuditLogRecord.created_at >= since)
        if until is not None:
            conditions.append(AuditLogRecord.created_at <= until)

        count_stmt = select(AuditLogRecord).where(*conditions)
        total_rows = (await self._session.execute(count_stmt)).scalars().all()
        total = len(total_rows)

        stmt = (
            select(AuditLogRecord)
            .where(*conditions)
            .order_by(AuditLogRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        return rows, total

    async def list_entries_cursor(
        self,
        org_id: str,
        *,
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> tuple[list[AuditLogRecord], str | None]:
        """Keyset cursor pagination, newest-first by ``(created_at, id)``.

        Returns ``(rows, next_cursor)``. ``next_cursor`` is ``None`` when the
        result set has been fully drained. The cursor is opaque and tied to
        ``org_id`` so it cannot leak rows across tenants.
        """
        conditions = [AuditLogRecord.org_id == org_id]

        if after_cursor is not None:
            try:
                payload = json.loads(
                    base64.urlsafe_b64decode(after_cursor.encode("ascii")).decode("utf-8")
                )
                last_created = datetime.fromisoformat(payload["c"])
                last_id = payload["i"]
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid cursor: {after_cursor!r}") from exc

            # Strict less-than on (created_at, id) — newest-first ordering.
            conditions.append(
                or_(
                    AuditLogRecord.created_at < last_created,
                    and_(
                        AuditLogRecord.created_at == last_created,
                        AuditLogRecord.id < last_id,
                    ),
                )
            )

        stmt = (
            select(AuditLogRecord)
            .where(*conditions)
            .order_by(
                AuditLogRecord.created_at.desc(),
                AuditLogRecord.id.desc(),
            )
            .limit(limit + 1)
        )
        rows = list((await self._session.execute(stmt)).scalars().all())

        if len(rows) > limit:
            rows = rows[:limit]
            tail = rows[-1]
            payload = {"c": tail.created_at.isoformat(), "i": tail.id}
            next_cursor = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode(
                "ascii"
            )
        else:
            next_cursor = None

        return rows, next_cursor
