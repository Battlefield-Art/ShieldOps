"""Onboarding progress DB persistence — TDD tests (#4).

Uses an isolated test-only Base + Record that matches the production model's
public field names. The repository operates on the model class reference,
so we inject our test model by reassigning the module-level `OnboardingProgressRecord`
lookup. This keeps tests fast and independent from the production mapper graph
(which has unrelated broken relationships that block SQLAlchemy configure).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shieldops.db.repositories.onboarding import (
    OnboardingProgressRepository,
    OnboardingStep,
)


class _TestBase(DeclarativeBase):
    pass


class _TestOnboardingRecord(_TestBase):
    """Isolated test clone of OnboardingProgressRecord — same public fields."""

    __tablename__ = "onboarding_progress_test"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"onb-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    step_name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("org_id", "step_name", name="uq_onboarding_test_org_step"),)


@pytest_asyncio.fixture()
async def session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    # Swap the record class inside the repository module so it uses our test model
    from shieldops.db.repositories import onboarding as onb_mod

    monkeypatch.setattr(onb_mod, "OnboardingProgressRecord", _TestOnboardingRecord)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture()
async def repo(session: AsyncSession) -> OnboardingProgressRepository:
    return OnboardingProgressRepository(session)


class TestOnboardingRepository:
    @pytest.mark.asyncio
    async def test_get_empty_returns_no_completed_steps(
        self, repo: OnboardingProgressRepository
    ) -> None:
        records = await repo.get_progress("org-a")
        assert records == []

    @pytest.mark.asyncio
    async def test_mark_step_persists_record(self, repo: OnboardingProgressRepository) -> None:
        await repo.mark_step_complete("org-a", OnboardingStep.SIGNUP)
        records = await repo.get_progress("org-a")
        assert len(records) == 1
        assert records[0].step_name == "signup"
        assert records[0].org_id == "org-a"
        assert records[0].completed_at is not None

    @pytest.mark.asyncio
    async def test_mark_step_is_idempotent(self, repo: OnboardingProgressRepository) -> None:
        await repo.mark_step_complete("org-a", OnboardingStep.SIGNUP)
        first = (await repo.get_progress("org-a"))[0]
        first_ts = first.completed_at
        # Second mark updates rather than inserts
        await repo.mark_step_complete("org-a", OnboardingStep.SIGNUP)
        records = await repo.get_progress("org-a")
        assert len(records) == 1
        assert records[0].completed_at >= first_ts

    @pytest.mark.asyncio
    async def test_tenant_isolation(self, repo: OnboardingProgressRepository) -> None:
        await repo.mark_step_complete("org-a", OnboardingStep.SIGNUP)
        await repo.mark_step_complete("org-b", OnboardingStep.EMAIL_VERIFIED)
        a_records = await repo.get_progress("org-a")
        b_records = await repo.get_progress("org-b")
        assert len(a_records) == 1 and a_records[0].step_name == "signup"
        assert len(b_records) == 1 and b_records[0].step_name == "email_verified"

    @pytest.mark.asyncio
    async def test_reset_removes_all_org_records(self, repo: OnboardingProgressRepository) -> None:
        await repo.mark_step_complete("org-a", OnboardingStep.SIGNUP)
        await repo.mark_step_complete("org-a", OnboardingStep.EMAIL_VERIFIED)
        await repo.mark_step_complete("org-b", OnboardingStep.SIGNUP)
        deleted = await repo.reset("org-a")
        assert deleted == 2
        assert await repo.get_progress("org-a") == []
        # org-b unaffected
        assert len(await repo.get_progress("org-b")) == 1

    @pytest.mark.asyncio
    async def test_full_flow(self, repo: OnboardingProgressRepository) -> None:
        for step in [
            OnboardingStep.SIGNUP,
            OnboardingStep.EMAIL_VERIFIED,
            OnboardingStep.API_KEY_CREATED,
            OnboardingStep.SDK_INSTALLED,
            OnboardingStep.FIRST_INTERCEPT,
            OnboardingStep.COMPLETE,
        ]:
            await repo.mark_step_complete("org-c", step)
        records = await repo.get_progress("org-c")
        assert len(records) == 6
        assert {r.step_name for r in records} == {
            "signup",
            "email_verified",
            "api_key_created",
            "sdk_installed",
            "first_intercept",
            "complete",
        }
