"""Incident similarity service — find past incidents matching a new alert.

Replaces ``Repository.get_similar_incidents`` and the related
``query_incident_outcomes`` aggregation. The "multi-entity" aspect
is the cross-table similarity scoring (alert_type + resource_id +
environment + outcome correctness).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models import IncidentOutcomeRecord

logger = structlog.get_logger(__name__)


class IncidentSimilarityService:
    """Find historical incidents similar to a new alert. ≤5 public methods."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def find_similar(
        self,
        alert_type: str,
        resource_id: str = "",
        environment: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return past incidents matching ``alert_type`` ranked by similarity.

        Scoring rules (kept simple — call sites currently treat similarity
        as a rough heuristic, not a calibrated probability):

        - Exact ``alert_type`` match: 0.8 base score
        - + ``resource_id`` substring in ``root_cause``: bumps to 0.9
        - + ``environment`` match: bumps to 0.95
        """
        async with self._sf() as session:
            stmt = (
                select(IncidentOutcomeRecord)
                .where(IncidentOutcomeRecord.alert_type == alert_type)
                .order_by(IncidentOutcomeRecord.created_at.desc())
                .limit(limit)
            )
            rows = (await session.execute(stmt)).scalars().all()

        out: list[dict[str, Any]] = []
        for r in rows:
            score = 0.8
            if resource_id and resource_id in (r.root_cause or ""):
                score = 0.9
            if environment and r.environment == environment:
                score = max(score, 0.95)
            out.append(
                {
                    "incident_id": r.id,
                    "alert_type": r.alert_type,
                    "root_cause": r.root_cause,
                    "resolution_action": r.resolution_action,
                    "similarity_score": score,
                    "was_correct": r.was_correct,
                    "environment": r.environment,
                }
            )
        return out

    async def query_recent(self, period: str = "30d", limit: int = 200) -> dict[str, Any]:
        """Return incidents in the trailing window for learning analysis."""
        days = int(period.rstrip("d")) if period.endswith("d") else 30
        cutoff = datetime.now(UTC) - timedelta(days=days)

        async with self._sf() as session:
            stmt = (
                select(IncidentOutcomeRecord)
                .where(IncidentOutcomeRecord.created_at >= cutoff)
                .order_by(IncidentOutcomeRecord.created_at.desc())
                .limit(limit)
            )
            rows = (await session.execute(stmt)).scalars().all()

        outcomes = [self._to_dict(r) for r in rows]
        return {"period": period, "total_incidents": len(outcomes), "outcomes": outcomes}

    async def count_by_environment(self, environment: str) -> int:
        """Return the total number of incidents recorded for ``environment``."""
        async with self._sf() as session:
            stmt = select(IncidentOutcomeRecord).where(
                IncidentOutcomeRecord.environment == environment
            )
            rows = (await session.execute(stmt)).scalars().all()
            return len(list(rows))

    @staticmethod
    def _to_dict(r: IncidentOutcomeRecord) -> dict[str, Any]:
        return {
            "incident_id": r.id,
            "alert_type": r.alert_type,
            "environment": r.environment,
            "root_cause": r.root_cause,
            "resolution_action": r.resolution_action,
            "investigation_id": r.investigation_id,
            "remediation_id": r.remediation_id,
            "investigation_duration_ms": r.investigation_duration_ms,
            "remediation_duration_ms": r.remediation_duration_ms,
            "was_automated": r.was_automated,
            "was_correct": r.was_correct,
            "feedback": r.feedback,
        }
