"""Design partner onboarding progress tracking (#213)."""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/onboarding", tags=["Onboarding"])

# Ordered steps of the onboarding flow
ONBOARDING_STEPS = [
    "signup",
    "email_verified",
    "api_key_created",
    "sdk_installed",
    "first_intercept",
    "complete",
]

# In-memory store: {org_id: {step: completed_at}}
_PROGRESS: dict[str, dict[str, datetime]] = {}


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


def _compute_progress(org_id: str) -> OnboardingProgress:
    completed = _PROGRESS.get(org_id, {})
    steps = [
        ProgressStep(
            step=s,
            completed=s in completed,
            completed_at=completed.get(s),
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
    return _compute_progress(_org(user))


@router.post("/progress", response_model=OnboardingProgress)
async def mark_step_complete(
    payload: StepUpdate,
    user: UserResponse = Depends(get_current_user),
) -> OnboardingProgress:
    """Mark a step as complete."""
    if payload.step not in ONBOARDING_STEPS:
        raise HTTPException(status_code=400, detail=f"unknown step: {payload.step}")
    org_id = _org(user)
    _PROGRESS.setdefault(org_id, {})[payload.step] = datetime.now(UTC)
    logger.info("onboarding.step_completed", org_id=org_id, step=payload.step)
    return _compute_progress(org_id)


def reset_progress() -> None:
    """Test helper."""
    _PROGRESS.clear()
