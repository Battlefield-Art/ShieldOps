"""Unit tests for the fitness-gated promotion engine."""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import agent_promotion
from shieldops.db.models_agent_status import AgentLifecycleStatus
from shieldops.utils.evolution.types import FitnessDimension
from shieldops.utils.fitness_aggregator import FitnessAggregator
from shieldops.utils.fitness_tracker import FitnessTracker
from shieldops.utils.promotion_engine import PromotionEngine

ONE_DAY = 24 * 3600


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def tracker() -> FitnessTracker:
    return FitnessTracker()


@pytest.fixture
def aggregator(tracker: FitnessTracker) -> FitnessAggregator:
    return FitnessAggregator(tracker=tracker)


@pytest.fixture
def engine(aggregator: FitnessAggregator) -> PromotionEngine:
    return PromotionEngine(aggregator=aggregator)


def _seed_daily(
    tracker: FitnessTracker,
    agent_name: str,
    values: list[float],
    *,
    end_ts: float | None = None,
) -> None:
    """Seed `values` as composite-equivalent daily observations.

    Each value is injected across the 5 fitness dimensions so the weighted
    composite equals ~value.
    """
    if end_ts is None:
        end_ts = time.time()
    for i, v in enumerate(values):
        day_ts = end_ts - (len(values) - 1 - i) * ONE_DAY
        for dim in FitnessDimension:
            obs = tracker.record(agent_name, dim, v)
            obs.timestamp = day_ts
            # Overwrite bucket timestamp so rolling_window sees correct day.
            tracker._observations[agent_name][dim][-1].timestamp = day_ts  # noqa: SLF001
        tracker._recompute(agent_name)  # noqa: SLF001


# ── Promotion tests ───────────────────────────────────────────────────


def test_promotion_criteria_7_days_above_threshold(
    engine: PromotionEngine, tracker: FitnessTracker
) -> None:
    """Agent with 7 consecutive days above 0.85 should be promoted."""
    _seed_daily(tracker, "alpha", [0.90, 0.91, 0.88, 0.87, 0.92, 0.90, 0.89])
    result = engine.evaluate_agent("alpha", org_id="acme")
    assert result.action == "promoted"
    assert result.previous_status == AgentLifecycleStatus.BETA
    assert result.new_status == AgentLifecycleStatus.GA
    assert engine.get_status("alpha", "acme").status == AgentLifecycleStatus.GA


def test_promotion_requires_consecutive_days(
    engine: PromotionEngine, tracker: FitnessTracker
) -> None:
    """A dip in the middle should prevent promotion."""
    _seed_daily(tracker, "bravo", [0.90, 0.91, 0.60, 0.87, 0.92, 0.90, 0.89])
    result = engine.evaluate_agent("bravo", org_id="acme")
    assert result.action == "none"
    assert result.new_status == AgentLifecycleStatus.BETA


def test_promotion_not_enough_days(engine: PromotionEngine, tracker: FitnessTracker) -> None:
    """Only 5 days above threshold should not promote."""
    _seed_daily(tracker, "charlie", [0.90, 0.91, 0.87, 0.92, 0.90])
    result = engine.evaluate_agent("charlie", org_id="acme")
    assert result.action == "none"


# ── Demotion tests ────────────────────────────────────────────────────


def test_demotion_criteria_24h_below_threshold(
    engine: PromotionEngine, tracker: FitnessTracker
) -> None:
    """GA agent whose latest day is below 0.70 should be demoted."""
    # First promote the agent — seed history ending two days ago.
    base = time.time() - 2 * ONE_DAY
    _seed_daily(tracker, "delta", [0.90] * 7, end_ts=base)
    engine.evaluate_agent("delta", org_id="acme", now=base)
    assert engine.get_status("delta", "acme").status == AgentLifecycleStatus.GA

    # Now inject a low-fitness trailing day strictly after the history.
    _seed_daily(tracker, "delta", [0.50], end_ts=time.time())
    result = engine.evaluate_agent("delta", org_id="acme")
    assert result.action == "demoted"
    assert result.new_status == AgentLifecycleStatus.BETA
    assert engine.get_status("delta", "acme").status == AgentLifecycleStatus.BETA


def test_no_demotion_when_within_threshold(
    engine: PromotionEngine, tracker: FitnessTracker
) -> None:
    """Healthy GA agent should not be demoted."""
    _seed_daily(tracker, "echo", [0.90] * 7)
    engine.evaluate_agent("echo", org_id="acme")
    # Another strong day.
    _seed_daily(tracker, "echo", [0.88])
    result = engine.evaluate_agent("echo", org_id="acme")
    assert result.action == "none"
    assert result.new_status == AgentLifecycleStatus.GA


# ── Manual promote / demote ───────────────────────────────────────────


def test_manual_promote_writes_audit(engine: PromotionEngine) -> None:
    snap = engine.promote_agent("foxtrot", org_id="acme", reason="qa sign-off")
    assert snap.status == AgentLifecycleStatus.GA
    assert snap.promoted_at is not None
    audit = engine.audit_log
    assert any(
        e["agent_name"] == "foxtrot" and e["action"] == "promoted" and e["manual"] is True
        for e in audit
    )


def test_manual_demote_can_disable(engine: PromotionEngine) -> None:
    engine.promote_agent("golf", org_id="acme", reason="launch")
    snap = engine.demote_agent("golf", org_id="acme", reason="incident", disable=True)
    assert snap.status == AgentLifecycleStatus.DISABLED


# ── Leaderboard ───────────────────────────────────────────────────────


def test_leaderboard_sorted_by_composite(engine: PromotionEngine, tracker: FitnessTracker) -> None:
    _seed_daily(tracker, "hotel", [0.70] * 7)
    _seed_daily(tracker, "india", [0.95] * 7)
    _seed_daily(tracker, "juliet", [0.82] * 7)
    for name in ("hotel", "india", "juliet"):
        engine.evaluate_agent(name, org_id="acme")

    board = engine.leaderboard(org_id="acme")
    assert [row["agent_name"] for row in board] == ["india", "juliet", "hotel"]
    assert board[0]["rank"] == 1
    assert board[0]["composite_fitness"] >= board[1]["composite_fitness"]


# ── Evaluation cycle ──────────────────────────────────────────────────


def test_run_evaluation_cycle_promotes_multiple(
    engine: PromotionEngine, tracker: FitnessTracker
) -> None:
    _seed_daily(tracker, "kilo", [0.90] * 7)
    _seed_daily(tracker, "lima", [0.91] * 7)
    _seed_daily(tracker, "mike", [0.40] * 7)  # should stay beta
    results = engine.run_evaluation_cycle(org_id="acme")
    promoted = [r for r in results if r.action == "promoted"]
    assert {r.agent_name for r in promoted} == {"kilo", "lima"}
    assert engine.get_status("mike", "acme").status == AgentLifecycleStatus.BETA


# ── API endpoint tests ────────────────────────────────────────────────


@pytest.fixture
def client(engine: PromotionEngine, tracker: FitnessTracker) -> TestClient:
    """FastAPI TestClient with promotion router mounted + auth stubbed."""

    app = FastAPI()
    app.include_router(agent_promotion.router, prefix="/api/v1")

    admin = UserResponse(
        id="u1", email="admin@example.com", name="Admin", role=UserRole.ADMIN, is_active=True
    )
    app.dependency_overrides[get_current_user] = lambda: admin

    # Patch engine accessor for the route module.
    agent_promotion._engine = lambda: engine  # type: ignore[assignment]
    # Patch the aggregator used in the history endpoint.
    from shieldops.utils import fitness_aggregator as fa_mod

    fa_mod._aggregator = engine._aggregator  # type: ignore[attr-defined]  # noqa: SLF001

    # Seed an agent so all API endpoints have data.
    _seed_daily(tracker, "november", [0.90] * 7)
    engine.evaluate_agent("november", org_id="acme")
    return TestClient(app)


def test_api_list_fitness(client: TestClient) -> None:
    resp = client.get("/api/v1/agents/fitness")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    names = {row["agent_name"] for row in data["items"]}
    assert "november" in names


def test_api_fitness_history(client: TestClient) -> None:
    resp = client.get("/api/v1/agents/november/fitness/history?window_days=7")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_name"] == "november"
    assert data["window_days"] == 7
    assert len(data["points"]) >= 1
    assert data["composite_current"] > 0.0


def test_api_leaderboard(client: TestClient) -> None:
    resp = client.get("/api/v1/agents/leaderboard?top_n=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert data["items"][0]["rank"] == 1


def test_api_manual_promote_demote(client: TestClient) -> None:
    promote = client.post(
        "/api/v1/agents/oscar/promote",
        json={"reason": "test", "org_id": "acme"},
    )
    assert promote.status_code == 200
    assert promote.json()["status"] == "ga"

    demote = client.post(
        "/api/v1/agents/oscar/demote",
        json={"reason": "rollback", "org_id": "acme"},
    )
    assert demote.status_code == 200
    assert demote.json()["status"] == "beta"


def test_api_non_admin_cannot_promote(engine: PromotionEngine, tracker: FitnessTracker) -> None:
    app = FastAPI()
    app.include_router(agent_promotion.router, prefix="/api/v1")
    viewer = UserResponse(
        id="u2", email="v@example.com", name="V", role=UserRole.VIEWER, is_active=True
    )
    app.dependency_overrides[get_current_user] = lambda: viewer
    agent_promotion._engine = lambda: engine  # type: ignore[assignment]

    client = TestClient(app)
    resp = client.post(
        "/api/v1/agents/papa/promote",
        json={"reason": "nope", "org_id": "acme"},
    )
    assert resp.status_code == 403
