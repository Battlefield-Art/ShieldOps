"""Onboarding route wired to repository — TDD tests (#1a).

Verifies that the onboarding_progress route delegates to the repository
(not an in-memory dict) and respects tenant isolation through the JWT.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.routes import onboarding_progress


class _FakeOnboardingRepo:
    """In-memory stand-in for OnboardingProgressRepository with the same interface."""

    def __init__(self) -> None:
        # (org_id, step_name) -> record
        self._rows: dict[tuple[str, str], Any] = {}

    async def get_progress(self, org_id: str) -> list[Any]:
        return [
            _Rec(org_id=k[0], step_name=k[1], completed_at=v)
            for k, v in sorted(self._rows.items(), key=lambda kv: kv[1])
            if k[0] == org_id
        ]

    async def mark_step_complete(self, org_id: str, step: Any) -> Any:
        step_value = getattr(step, "value", step)
        now = datetime.now(UTC)
        self._rows[(org_id, step_value)] = now
        return _Rec(org_id=org_id, step_name=step_value, completed_at=now)

    async def reset(self, org_id: str) -> int:
        keys = [k for k in self._rows if k[0] == org_id]
        for k in keys:
            del self._rows[k]
        return len(keys)


class _Rec:
    def __init__(self, *, org_id: str, step_name: str, completed_at: datetime) -> None:
        self.org_id = org_id
        self.step_name = step_name
        self.completed_at = completed_at


def _user_factory(org_id: str):  # noqa: ANN202
    async def _user() -> MagicMock:
        u = MagicMock()
        u.org_id = org_id
        u.id = "test-user"
        return u

    return _user


@pytest.fixture()
def repo() -> _FakeOnboardingRepo:
    return _FakeOnboardingRepo()


@pytest.fixture()
def app(repo: _FakeOnboardingRepo) -> FastAPI:
    onboarding_progress.set_repository(repo)
    a = FastAPI()
    a.include_router(onboarding_progress.router)
    a.dependency_overrides[get_current_user] = _user_factory("org-a")
    yield a
    onboarding_progress.set_repository(None)


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


class TestRouteUsesRepository:
    def test_empty_progress_reads_from_repo(
        self, client: TestClient, repo: _FakeOnboardingRepo
    ) -> None:
        assert repo._rows == {}
        r = client.get("/onboarding/progress")
        assert r.status_code == 200
        data = r.json()
        assert data["percent_complete"] == 0.0
        assert data["current_step"] == "signup"

    def test_mark_step_writes_through_repo(
        self, client: TestClient, repo: _FakeOnboardingRepo
    ) -> None:
        r = client.post("/onboarding/progress", json={"step": "signup"})
        assert r.status_code == 200
        # Verify the repository received the write, not some module-level dict
        assert ("org-a", "signup") in repo._rows

    def test_progress_reflects_repo_state(
        self, client: TestClient, repo: _FakeOnboardingRepo
    ) -> None:
        import asyncio

        asyncio.run(repo.mark_step_complete("org-a", "signup"))
        asyncio.run(repo.mark_step_complete("org-a", "email_verified"))
        r = client.get("/onboarding/progress")
        data = r.json()
        assert data["current_step"] == "api_key_created"
        # 2/6 complete ≈ 33.3
        assert 33.0 <= data["percent_complete"] <= 34.0
