"""Design partner onboarding progress tracking (#213, #1a-wire-repo).

Persists progress via :class:`OnboardingProgressRepository`. Tests inject a
fake repo via :func:`set_repository`; production wires to a real async DB
session in ``api/app.py`` lifespan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/onboarding", tags=["Onboarding"])

# Canonical ordered flow — must stay in sync with OnboardingStep enum.
ONBOARDING_STEPS = [
    "signup",
    "email_verified",
    "api_key_created",
    "sdk_installed",
    "first_intercept",
    "complete",
]


class _RepoProtocol(Protocol):
    async def get_progress(self, org_id: str) -> list[Any]: ...
    async def mark_step_complete(self, org_id: str, step: Any) -> Any: ...
    async def reset(self, org_id: str) -> int: ...


# Injected at startup (tests: via set_repository; prod: via app.py lifespan).
_repository: _RepoProtocol | None = None


def set_repository(repo: _RepoProtocol | None) -> None:
    """Inject the onboarding progress repository."""
    global _repository
    _repository = repo


def _get_repository() -> _RepoProtocol:
    if _repository is None:
        raise HTTPException(status_code=503, detail="Onboarding repository not initialized")
    return _repository


class ProgressStep(BaseModel):
    step: str
    completed: bool
    completed_at: datetime | None = None


class OnboardingProgress(BaseModel):
    org_id: str
    current_step: str
    percent_complete: float
    steps: list[ProgressStep] = Field(default_factory=list)


class StepUpdate(BaseModel):
    step: str


def _org(user: UserResponse) -> str:
    return (
        getattr(user, "org_id", None)
        or getattr(user, "tenant_id", None)
        or getattr(user, "id", "default")
    )


async def _compute_progress_async(org_id: str, repo: _RepoProtocol) -> OnboardingProgress:
    records = await repo.get_progress(org_id)
    completed_map: dict[str, datetime] = {r.step_name: r.completed_at for r in records}
    steps = [
        ProgressStep(
            step=s,
            completed=s in completed_map,
            completed_at=completed_map.get(s),
        )
        for s in ONBOARDING_STEPS
    ]
    done = sum(1 for s in steps if s.completed)
    current = next((s.step for s in steps if not s.completed), "complete")
    return OnboardingProgress(
        org_id=org_id,
        current_step=current,
        percent_complete=round(100.0 * done / len(ONBOARDING_STEPS), 1),
        steps=steps,
    )


@router.get("/progress", response_model=OnboardingProgress)
async def get_progress(
    user: UserResponse = Depends(get_current_user),
) -> OnboardingProgress:
    """Get the onboarding progress for the current org."""
    repo = _get_repository()
    return await _compute_progress_async(_org(user), repo)


@router.post("/progress", response_model=OnboardingProgress)
async def mark_step_complete(
    payload: StepUpdate,
    user: UserResponse = Depends(get_current_user),
) -> OnboardingProgress:
    """Mark a step as complete."""
    if payload.step not in ONBOARDING_STEPS:
        raise HTTPException(status_code=400, detail=f"unknown step: {payload.step}")
    repo = _get_repository()
    org_id = _org(user)
    await repo.mark_step_complete(org_id, payload.step)
    logger.info("onboarding.step_completed", org_id=org_id, step=payload.step)
    return await _compute_progress_async(org_id, repo)


def reset_progress() -> None:
    """Test helper kept for legacy tests — no-op when using the DB repo."""
