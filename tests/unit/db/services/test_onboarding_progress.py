"""Contract tests for OnboardingProgressService — RFC #245 PR-4 / #273."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tests.unit.db.services.conftest import FakeOnboardingProgress, SvcBase


@pytest_asyncio.fixture()
async def session_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[async_sessionmaker]:
    from shieldops.db.repositories import onboarding as repo_mod

    monkeypatch.setattr(repo_mod, "OnboardingProgressRecord", FakeOnboardingProgress)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SvcBase.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture()
async def service(session_factory: async_sessionmaker):
    from shieldops.db.services.onboarding_progress import OnboardingProgressService

    return OnboardingProgressService(session_factory)


class TestConstruction:
    def test_constructor_holds_session_factory(self, session_factory) -> None:
        from shieldops.db.services.onboarding_progress import OnboardingProgressService

        svc = OnboardingProgressService(session_factory)
        assert svc._sf is session_factory


class TestGetState:
    @pytest.mark.asyncio
    async def test_state_for_new_org_is_empty(self, service) -> None:
        state = await service.get_state("org-new")
        assert state["org_id"] == "org-new"
        assert state["completed_steps"] == []
        assert state["next_step"] == "signup"
        assert state["percent_complete"] == 0.0
        assert state["is_complete"] is False

    @pytest.mark.asyncio
    async def test_state_after_partial_completion(self, service) -> None:
        await service.mark_complete("org-1", "signup")
        state = await service.get_state("org-1")
        assert "signup" in state["completed_steps"]
        assert state["next_step"] == "email_verified"
        assert 0.0 < state["percent_complete"] < 1.0
        assert state["is_complete"] is False


class TestMarkComplete:
    @pytest.mark.asyncio
    async def test_mark_complete_returns_updated_state(self, service) -> None:
        from shieldops.db.repositories.onboarding import OnboardingStep

        state = await service.mark_complete("org-2", OnboardingStep.SIGNUP)
        assert "signup" in state["completed_steps"]
        assert state["next_step"] != "signup"

    @pytest.mark.asyncio
    async def test_marking_all_steps_completes_onboarding(self, service) -> None:
        from shieldops.db.services.onboarding_progress import ONBOARDING_SEQUENCE

        for step in ONBOARDING_SEQUENCE:
            await service.mark_complete("org-3", step)
        state = await service.get_state("org-3")
        assert state["is_complete"] is True
        assert state["next_step"] is None
        assert state["percent_complete"] == 1.0


class TestReset:
    @pytest.mark.asyncio
    async def test_reset_wipes_progress(self, service) -> None:
        await service.mark_complete("org-4", "signup")
        deleted = await service.reset("org-4")
        assert deleted >= 1
        state = await service.get_state("org-4")
        assert state["completed_steps"] == []
