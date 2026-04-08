"""Investigation write service — compound 'create + seed audit' write path.

Replaces the multi-table write side of the deleted ``Repository``:
upserting an investigation, recording the matching audit-log entry,
and (optionally) seeding an initial timeline event — all in a single
transaction so callers don't have to coordinate commits.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models import AuditLog, InvestigationRecord

logger = structlog.get_logger(__name__)


class InvestigationWriteService:
    """Compound write path for investigations + audit. ≤5 public methods."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def create_with_audit(
        self,
        investigation_id: str,
        alert_id: str,
        alert_name: str,
        severity: str = "warning",
        actor: str = "agent:investigation",
        environment: str = "prod",
        reasoning: str = "",
    ) -> dict[str, Any]:
        """Create an investigation row + matching audit-log entry atomically.

        Returns the created investigation as a dict. If the investigation
        already exists, this is a no-op for the investigation row but
        still appends a fresh audit entry (audit log is append-only).
        """
        async with self._sf() as session:
            inv = await self._upsert_investigation(
                session,
                investigation_id=investigation_id,
                alert_id=alert_id,
                alert_name=alert_name,
                severity=severity,
            )
            audit = AuditLog(
                id=f"aud-{uuid4().hex[:12]}",
                timestamp=datetime.now(UTC),
                agent_type="investigation",
                action="investigation_created",
                target_resource=alert_id,
                environment=environment,
                risk_level=severity,
                policy_evaluation="allowed",
                approval_status=None,
                outcome="success",
                reasoning=reasoning or f"investigation {investigation_id}",
                actor=actor,
            )
            session.add(audit)
            await session.commit()
            await session.refresh(inv)

        logger.info(
            "investigation.created_with_audit",
            investigation_id=investigation_id,
            alert_id=alert_id,
        )
        return {
            "id": inv.id,
            "alert_id": inv.alert_id,
            "alert_name": inv.alert_name,
            "severity": inv.severity,
            "status": inv.status,
        }

    async def update_status(
        self,
        investigation_id: str,
        status: str,
        actor: str = "agent:investigation",
        environment: str = "prod",
    ) -> bool:
        """Update an investigation's status and append an audit entry.

        Returns ``True`` on success, ``False`` if the investigation
        doesn't exist.
        """
        async with self._sf() as session:
            inv = await session.get(InvestigationRecord, investigation_id)
            if inv is None:
                return False
            inv.status = status
            audit = AuditLog(
                id=f"aud-{uuid4().hex[:12]}",
                timestamp=datetime.now(UTC),
                agent_type="investigation",
                action=f"investigation_status_{status}",
                target_resource=inv.alert_id,
                environment=environment,
                risk_level=inv.severity,
                policy_evaluation="allowed",
                approval_status=None,
                outcome="success",
                reasoning=f"investigation {investigation_id} -> {status}",
                actor=actor,
            )
            session.add(audit)
            await session.commit()
        return True

    # ── helpers ───────────────────────────────────────────────────

    @staticmethod
    async def _upsert_investigation(
        session: AsyncSession,
        *,
        investigation_id: str,
        alert_id: str,
        alert_name: str,
        severity: str,
    ) -> InvestigationRecord:
        existing = await session.get(InvestigationRecord, investigation_id)
        if existing is not None:
            return existing
        inv = InvestigationRecord(
            id=investigation_id,
            alert_id=alert_id,
            alert_name=alert_name,
            severity=severity,
            status="init",
        )
        session.add(inv)
        await session.flush()
        return inv
