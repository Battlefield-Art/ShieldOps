"""Async repository for onboarding progress persistence (#4)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from shieldops.db.models import OnboardingProgressRecord

logger = structlog.get_logger(__name__)


class OnboardingStep(StrEnum):
    SIGNUP = "signup"
    EMAIL_VERIFIED = "email_verified"
    API_KEY_CREATED = "api_key_created"
    SDK_INSTALLED = "sdk_installed"
    FIRST_INTERCEPT = "first_intercept"
    COMPLETE = "complete"


class OnboardingProgressRepository:
    """Persists onboarding progress in Postgres (or SQLite for tests).

    Wraps the existing ``onboarding_progress`` table. Idempotent upsert
    semantics on (org_id, step_name).
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_progress(self, org_id: str) -> list[OnboardingProgressRecord]:
        """Return completed steps for ``org_id``, ordered by completion time."""
        stmt = (
            select(OnboardingProgressRecord)
            .where(
                OnboardingProgressRecord.org_id == org_id,
                OnboardingProgressRecord.status == "completed",
            )
            .order_by(OnboardingProgressRecord.completed_at)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def mark_step_complete(
        self, org_id: str, step: OnboardingStep | str
    ) -> OnboardingProgressRecord:
        """Mark ``step`` as complete for ``org_id``. Idempotent."""
        step_value = step.value if isinstance(step, OnboardingStep) else step
        now = datetime.now(UTC)

        stmt = select(OnboardingProgressRecord).where(
            OnboardingProgressRecord.org_id == org_id,
            OnboardingProgressRecord.step_name == step_value,
        )
        existing = (await self._session.execute(stmt)).scalar_one_or_none()
        if existing is not None:
            existing.status = "completed"
            existing.completed_at = now
            await self._session.commit()
            await self._session.refresh(existing)
            return existing

        record = OnboardingProgressRecord(
            org_id=org_id,
            step_name=step_value,
            status="completed",
            completed_at=now,
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        logger.info("onboarding.step_persisted", org_id=org_id, step=step_value)
        return record

    async def reset(self, org_id: str) -> int:
        """Delete all progress records for ``org_id``. Returns count deleted."""
        stmt = delete(OnboardingProgressRecord).where(OnboardingProgressRecord.org_id == org_id)
        result = await self._session.execute(stmt)
        await self._session.commit()
        return result.rowcount or 0
