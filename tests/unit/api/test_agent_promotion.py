"""Tests for ``api/routes/agent_promotion.py`` backed by ``EvolutionStore``.

RFC #246 PR-5 (#278): verifies the route wires through
``Depends(get_evolution_store)`` and no longer touches the legacy
``fitness_aggregator`` / ``promotion_engine`` singletons.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import agent_promotion
from shieldops.utils.evolution.composition import set_evolution_store
from shieldops.utils.evolution.store import EvolutionStore, RunOutcome

# ── Fixtures ──────────────────────────────────────────────────────────


def _make_user(role: UserRole) -> UserResponse:
    return UserResponse(
        id="test-user",
        email="tester@example.com",
        name="Tester",
        role=role,
        is_active=True,
    )


def _user_factory(role: UserRole):  # noqa: ANN202
    async def _u() -> UserResponse:
        return _make_user(role)

    return _u


@pytest.fixture()
def store() -> Iterator[EvolutionStore]:
    s = EvolutionStore.in_memory()
    # Seed fitness for two agents so leaderboards are non-empty.
    for _ in range(3):
        s.record_run("alpha", RunOutcome(success=True, latency_ms=100, cost_usd=0.01))
    for _ in range(3):
        s.record_run("beta", RunOutcome(success=False, latency_ms=500, cost_usd=0.02))
    set_evolution_store(s)
    try:
        yield s
    finally:
        set_evolution_store(None)


@pytest.fixture()
def admin_app(store: EvolutionStore) -> FastAPI:
    app = FastAPI()
    app.include_router(agent_promotion.router)
    app.dependency_overrides[get_current_user] = _user_factory(UserRole.ADMIN)
    return app


@pytest.fixture()
def viewer_app(store: EvolutionStore) -> FastAPI:
    app = FastAPI()
    app.include_router(agent_promotion.router)
    app.dependency_overrides[get_current_user] = _user_factory(UserRole.VIEWER)
    return app


@pytest.fixture()
def admin_client(admin_app: FastAPI) -> TestClient:
    return TestClient(admin_app)


@pytest.fixture()
def viewer_client(viewer_app: FastAPI) -> TestClient:
    return TestClient(viewer_app)


# ── Tests ─────────────────────────────────────────────────────────────


class TestListFitness:
    def test_list_includes_both_agents(self, admin_client: TestClient) -> None:
        r = admin_client.get("/agents/fitness")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        names = {row["agent_name"] for row in data["items"]}
        assert names == {"alpha", "beta"}
        # Response shape is preserved: every row has these fields.
        for row in data["items"]:
            assert set(row.keys()) == {
                "agent_name",
                "org_id",
                "status",
                "composite_fitness",
                "promoted_at",
                "demoted_at",
                "rank",
            }
            assert row["org_id"] == "default"
            assert row["status"] == "active"
            assert isinstance(row["composite_fitness"], (int, float))


class TestLeaderboard:
    def test_leaderboard_sorted_by_fitness(self, admin_client: TestClient) -> None:
        r = admin_client.get("/agents/leaderboard?top_n=10")
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 2
        # alpha (success=True) should outrank beta (success=False).
        assert items[0]["agent_name"] == "alpha"
        assert items[1]["agent_name"] == "beta"
        assert items[0]["rank"] == 1
        assert items[1]["rank"] == 2
        assert items[0]["composite_fitness"] >= items[1]["composite_fitness"]


class TestFitnessHistory:
    def test_history_shape_preserved(self, admin_client: TestClient) -> None:
        r = admin_client.get("/agents/alpha/fitness/history?window_days=7")
        assert r.status_code == 200
        data = r.json()
        assert data["agent_name"] == "alpha"
        assert data["window_days"] == 7
        assert data["sample_count"] >= 1
        assert isinstance(data["points"], list)
        assert len(data["points"]) >= 1
        pt = data["points"][0]
        assert set(pt.keys()) == {
            "day_epoch",
            "composite",
            "dimensions",
            "sample_count",
        }

    def test_history_unknown_agent_is_empty(self, admin_client: TestClient) -> None:
        r = admin_client.get("/agents/ghost/fitness/history")
        assert r.status_code == 200
        data = r.json()
        assert data["agent_name"] == "ghost"
        assert data["sample_count"] == 0
        assert data["points"] == []


class TestPromote:
    def test_admin_can_promote(self, admin_client: TestClient, store: EvolutionStore) -> None:
        r = admin_client.post(
            "/agents/alpha/promote",
            json={"reason": "high accuracy", "org_id": "default"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["agent_name"] == "alpha"
        assert data["status"] == "promoted"
        assert data["action"] == "promoted"
        assert data["reason"] == "high accuracy"
        assert data["composite_fitness"] > 0
        # Confirm the store actually recorded the promotion.
        rows = store.leaderboard_rows()
        alpha_row = next(r for r in rows if r["agent_name"] == "alpha")
        assert alpha_row["status"] == "promoted"
        assert alpha_row["promoted_at"] is not None

    def test_viewer_is_forbidden(self, viewer_client: TestClient) -> None:
        r = viewer_client.post(
            "/agents/alpha/promote",
            json={"reason": "nope"},
        )
        assert r.status_code == 403
        assert "admin" in r.json()["detail"].lower()

    def test_unknown_agent_returns_404(self, admin_client: TestClient) -> None:
        r = admin_client.post(
            "/agents/phantom/promote",
            json={"reason": "test"},
        )
        assert r.status_code == 404


class TestDemote:
    def test_admin_can_demote(self, admin_client: TestClient, store: EvolutionStore) -> None:
        r = admin_client.post(
            "/agents/beta/demote",
            json={"reason": "low accuracy", "disable": False},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["agent_name"] == "beta"
        assert data["status"] == "demoted"
        assert data["action"] == "demoted"

    def test_admin_can_disable(self, admin_client: TestClient) -> None:
        r = admin_client.post(
            "/agents/beta/demote",
            json={"reason": "unsafe", "disable": True},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "disabled"

    def test_viewer_is_forbidden(self, viewer_client: TestClient) -> None:
        r = viewer_client.post(
            "/agents/beta/demote",
            json={"reason": "nope"},
        )
        assert r.status_code == 403
