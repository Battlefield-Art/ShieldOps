"""Investigation timeline service — joins investigations + remediations + audit log.

Replaces the cross-entity ``Repository.get_investigation_timeline`` method
that the deleted ``repository.py`` exposed (RFC #245 PR-3).

Builds a chronologically-merged timeline view of every event tied to
an investigation: the investigation record itself, all remediations
that reference it via ``investigation_id``, and any audit-log entries
whose ``reasoning`` field mentions the investigation id.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models import AuditLog, InvestigationRecord, RemediationRecord

logger = structlog.get_logger(__name__)


class InvestigationTimelineService:
    """Build merged timelines that span 3 tables. ≤5 public methods."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def build_timeline(self, investigation_id: str) -> list[dict[str, Any]]:
        """Return the merged, chronologically-sorted timeline for ``investigation_id``.

        Returns an empty list if the investigation does not exist (caller
        is responsible for issuing a 404 if that matters).
        """
        events: list[dict[str, Any]] = []

        async with self._sf() as session:
            inv = await session.get(InvestigationRecord, investigation_id)
            if inv is not None:
                events.extend(self._investigation_events(inv))

            events.extend(await self._remediation_events(session, investigation_id))
            events.extend(await self._audit_events(session, investigation_id))

        events.sort(key=lambda e: e.get("timestamp") or "")
        return events

    async def filter_by_type(self, investigation_id: str, event_type: str) -> list[dict[str, Any]]:
        """Return only events whose ``type`` matches ``event_type``."""
        all_events = await self.build_timeline(investigation_id)
        return [e for e in all_events if e.get("type") == event_type]

    async def count_events(self, investigation_id: str) -> int:
        """Return the total number of timeline events for ``investigation_id``."""
        return len(await self.build_timeline(investigation_id))

    # ── helpers ────────────────────────────────────────────────────

    @staticmethod
    def _investigation_events(inv: InvestigationRecord) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [
            {
                "id": f"inv-{inv.id}",
                "timestamp": inv.created_at.isoformat() if inv.created_at else None,
                "type": "investigation",
                "action": f"investigation_{inv.status or 'started'}",
                "actor": "agent:investigation",
                "severity": inv.severity,
                "details": {
                    "alert_id": inv.alert_id,
                    "alert_name": inv.alert_name,
                    "confidence": inv.confidence,
                    "duration_ms": inv.duration_ms,
                    "error": inv.error,
                },
            }
        ]
        if inv.updated_at and inv.created_at and inv.updated_at != inv.created_at:
            out.append(
                {
                    "id": f"inv-{inv.id}-updated",
                    "timestamp": inv.updated_at.isoformat(),
                    "type": "investigation",
                    "action": f"investigation_{inv.status or 'updated'}",
                    "actor": "agent:investigation",
                    "severity": inv.severity,
                    "details": {"alert_id": inv.alert_id, "confidence": inv.confidence},
                }
            )
        return out

    @staticmethod
    async def _remediation_events(
        session: AsyncSession, investigation_id: str
    ) -> list[dict[str, Any]]:
        stmt = (
            select(RemediationRecord)
            .where(RemediationRecord.investigation_id == investigation_id)
            .order_by(RemediationRecord.created_at.asc())
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": f"rem-{r.id}",
                "timestamp": r.created_at.isoformat() if r.created_at else None,
                "type": "remediation",
                "action": f"{r.action_type}_{r.status}",
                "actor": "agent:remediation",
                "severity": r.risk_level,
                "details": {
                    "remediation_id": r.id,
                    "action_type": r.action_type,
                    "target_resource": r.target_resource,
                    "environment": r.environment,
                    "validation_passed": r.validation_passed,
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                },
            }
            for r in rows
        ]

    @staticmethod
    async def _audit_events(session: AsyncSession, investigation_id: str) -> list[dict[str, Any]]:
        stmt = (
            select(AuditLog)
            .where(AuditLog.reasoning.ilike(f"%{investigation_id}%"))
            .order_by(AuditLog.timestamp.asc())
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": f"aud-{a.id}",
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "type": "audit",
                "action": a.action,
                "actor": a.actor,
                "severity": a.risk_level,
                "details": {
                    "audit_id": a.id,
                    "agent_type": a.agent_type,
                    "target_resource": a.target_resource,
                    "environment": a.environment,
                    "policy_evaluation": a.policy_evaluation,
                    "approval_status": a.approval_status,
                    "outcome": a.outcome,
                    "reasoning": a.reasoning,
                },
            }
            for a in rows
        ]
