"""Onboarding progress aggregation service.

The single-step row CRUD lives in
:class:`shieldops.db.repositories.onboarding.OnboardingProgressRepository`
(per-session). This service is the *cross-row aggregation* layer
that callers actually want from the API: "what fraction of the
required steps has org X completed, and what's the next step?".

Wraps the row-level repo with a session-factory so route handlers
get the same DI shape as the other named services.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.repositories.onboarding import (
    OnboardingProgressRepository,
    OnboardingStep,
)

logger = structlog.get_logger(__name__)

# Canonical onboarding sequence — this is the wizard order.
ONBOARDING_SEQUENCE: tuple[OnboardingStep, ...] = (
    OnboardingStep.SIGNUP,
    OnboardingStep.EMAIL_VERIFIED,
    OnboardingStep.API_KEY_CREATED,
    OnboardingStep.SDK_INSTALLED,
    OnboardingStep.FIRST_INTERCEPT,
    OnboardingStep.COMPLETE,
)


class OnboardingProgressService:
    """Aggregate onboarding state for an org. ≤5 public methods."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def get_state(self, org_id: str) -> dict[str, Any]:
        """Return aggregated onboarding state for ``org_id``.

        Shape::

            {
                "org_id": "...",
                "completed_steps": ["signup", ...],
                "next_step": "api_key_created" | None,
                "percent_complete": 0.5,
                "is_complete": False,
            }
        """
        completed = await self._completed_step_names(org_id)
        completed_set = set(completed)

        next_step: str | None = None
        for step in ONBOARDING_SEQUENCE:
            if step.value not in completed_set:
                next_step = step.value
                break

        total = len(ONBOARDING_SEQUENCE)
        percent = round(len(completed_set & {s.value for s in ONBOARDING_SEQUENCE}) / total, 4)

        return {
            "org_id": org_id,
            "completed_steps": completed,
            "next_step": next_step,
            "percent_complete": percent,
            "is_complete": next_step is None,
        }

    async def mark_complete(self, org_id: str, step: OnboardingStep | str) -> dict[str, Any]:
        """Mark a step complete and return the updated aggregated state."""
        async with self._sf() as session:
            repo = OnboardingProgressRepository(session)
            await repo.mark_step_complete(org_id, step)
        return await self.get_state(org_id)

    async def reset(self, org_id: str) -> int:
        """Wipe all progress for ``org_id``. Returns rows deleted."""
        async with self._sf() as session:
            repo = OnboardingProgressRepository(session)
            return await repo.reset(org_id)

    # ── helpers ───────────────────────────────────────────────────

    async def _completed_step_names(self, org_id: str) -> list[str]:
        async with self._sf() as session:
            repo = OnboardingProgressRepository(session)
            rows = await repo.get_progress(org_id)
        return [r.step_name for r in rows]
