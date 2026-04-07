"""Unified audit log write path — RFC #245 PR-1.

See ghantakiran/ShieldOps#245. This module provides the single
``audit.log_audit`` function that every audit write in the codebase
should go through. Today the codebase has two parallel audit-log
paths:

- ``repositories/audit_entry.py`` → ``audit_entries`` table
- ``repositories/audit_log.py``   → ``shieldops_audit_log`` table

RFC #245 Phase 2 picks ``shieldops_audit_log`` as the winner and
backfills the old table via an Alembic migration. PR-1 (this module)
just adds the unified write path that can later be flipped to the
single canonical table.

In PR-1, this function writes to whichever table the underlying
``AuditLogRepository`` currently targets — the migration to the
canonical table is a PR-2 concern. The key win from PR-1 is that
**new code** can use ``audit.log_audit`` instead of having to pick
between two repositories.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from shieldops.db.repositories.audit_log import AuditLogRepository


async def log_audit(
    session: AsyncSession,
    *,
    org_id: str,
    action: str,
    actor: str = "",
    target: str = "",
    result: str = "",
    metadata: dict[str, Any] | None = None,
) -> Any:
    """Write a single audit-log entry to the canonical table.

    This is the one write path any new code should use. Existing
    call sites that go through ``AuditEntryRepository`` or
    ``AuditLogRepository`` directly keep working during the
    migration window; PR-2 will codemod them to this function.

    Returns the persisted record so callers can assert on its id
    in tests without re-querying.
    """
    repo = AuditLogRepository(session)
    return await repo.append(
        org_id=org_id,
        action=action,
        actor=actor,
        target=target,
        result=result,
        metadata=metadata or {},
    )
