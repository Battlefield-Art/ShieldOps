"""Compliance export service — bundles cross-table evidence for an audit period.

Aggregates investigations, remediations, and audit-log entries within a
date range and emits a single evidence bundle suitable for SOC 2 / ISO
27001 auditor handoff. This is a multi-table read that the deleted
``Repository`` god-object used to expose ad-hoc; it now lives here as
a focused service.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models import AuditLog, InvestigationRecord, RemediationRecord

logger = structlog.get_logger(__name__)


class ComplianceExportService:
    """Bundle evidence rows from 3 tables for a compliance window."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def export_bundle(
        self,
        period_days: int = 30,
        environment: str | None = None,
    ) -> dict[str, Any]:
        """Return a complete evidence bundle for the trailing ``period_days``.

        Bundle structure::

            {
                "period_days": 30,
                "generated_at": "...",
                "investigations": [...],
                "remediations": [...],
                "audit_log": [...],
                "totals": {"investigations": N, "remediations": N, "audit": N},
            }
        """
        cutoff = datetime.now(UTC) - timedelta(days=period_days)

        async with self._sf() as session:
            investigations = await self._fetch_investigations(session, cutoff)
            remediations = await self._fetch_remediations(session, cutoff, environment)
            audit_entries = await self._fetch_audit(session, cutoff, environment)

        return {
            "period_days": period_days,
            "environment": environment,
            "generated_at": datetime.now(UTC).isoformat(),
            "investigations": investigations,
            "remediations": remediations,
            "audit_log": audit_entries,
            "totals": {
                "investigations": len(investigations),
                "remediations": len(remediations),
                "audit": len(audit_entries),
            },
        }

    async def summary_counts(self, period_days: int = 30) -> dict[str, int]:
        """Return only row-counts per table for a fast dashboard tile."""
        bundle = await self.export_bundle(period_days=period_days)
        return dict(bundle["totals"])

    # ── helpers ───────────────────────────────────────────────────

    @staticmethod
    async def _fetch_investigations(
        session: AsyncSession, cutoff: datetime
    ) -> list[dict[str, Any]]:
        stmt = (
            select(InvestigationRecord)
            .where(InvestigationRecord.created_at >= cutoff)
            .order_by(InvestigationRecord.created_at.desc())
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "severity": r.severity,
                "status": r.status,
                "confidence": r.confidence,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    @staticmethod
    async def _fetch_remediations(
        session: AsyncSession, cutoff: datetime, environment: str | None
    ) -> list[dict[str, Any]]:
        stmt = select(RemediationRecord).where(RemediationRecord.created_at >= cutoff)
        if environment is not None:
            stmt = stmt.where(RemediationRecord.environment == environment)
        stmt = stmt.order_by(RemediationRecord.created_at.desc())
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": r.id,
                "action_type": r.action_type,
                "target_resource": r.target_resource,
                "environment": r.environment,
                "status": r.status,
                "validation_passed": r.validation_passed,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    @staticmethod
    async def _fetch_audit(
        session: AsyncSession, cutoff: datetime, environment: str | None
    ) -> list[dict[str, Any]]:
        stmt = select(AuditLog).where(AuditLog.timestamp >= cutoff)
        if environment is not None:
            stmt = stmt.where(AuditLog.environment == environment)
        stmt = stmt.order_by(AuditLog.timestamp.desc())
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "action": a.action,
                "actor": a.actor,
                "outcome": a.outcome,
                "environment": a.environment,
                "policy_evaluation": a.policy_evaluation,
            }
            for a in rows
        ]
