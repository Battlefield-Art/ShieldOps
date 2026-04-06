"""Tests for the agent metrics dashboard API.

Covers the three endpoints exposed by ``shieldops.api.routes.agent_metrics_api``:

- ``GET /api/v1/agents/metrics``          → per-agent aggregation
- ``GET /api/v1/agents/metrics/fleet``    → fleet totals
- ``GET /api/v1/agents/metrics/trends``   → bucketed trend series

Repository aggregation calls are stubbed so tests avoid a real database.
A fresh FastAPI instance is built per test (mirrors ``test_audit_routes.py``)
to side-step the full ``app.lifespan`` startup flow.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import agent_metrics_api


def _make_user() -> UserResponse:
    return UserResponse(
        id="user-1",
        email="tester@shieldops.ai",
        name="Tester",
        role=UserRole.ADMIN,
        is_active=True,
    )


def _build_app(repo: AsyncMock | None) -> FastAPI:
    """Build a minimal FastAPI app with the metrics router and auth override."""
    agent_metrics_api._run_repo = repo
    app = FastAPI()
    app.include_router(agent_metrics_api.router, prefix="/api/v1")

    async def _override_user() -> UserResponse:
        return _make_user()

    app.dependency_overrides[get_current_user] = _override_user
    return app


@pytest.fixture()
def mock_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.aggregate_by_agent = AsyncMock(
        return_value=[
            {
                "agent_name": "investigation",
                "total_runs": 120,
                "success_count": 110,
                "failure_count": 10,
                "success_rate": 0.9167,
                "avg_duration_ms": 4200.5,
                "max_duration_ms": 15000,
                "total_tokens": 480_000,
                "estimated_cost_usd": 4.32,
            },
            {
                "agent_name": "remediation",
                "total_runs": 40,
                "success_count": 38,
                "failure_count": 2,
                "success_rate": 0.95,
                "avg_duration_ms": 9800.0,
                "max_duration_ms": 22000,
                "total_tokens": 200_000,
                "estimated_cost_usd": 1.80,
            },
        ]
    )
    repo.aggregate_fleet = AsyncMock(
        return_value={
            "range": "24h",
            "total_agents": 2,
            "total_runs": 160,
            "total_success": 148,
            "total_failure": 12,
            "fleet_success_rate": 0.925,
            "avg_duration_ms": 5600.0,
            "total_tokens": 680_000,
            "estimated_cost_usd": 6.12,
        }
    )
    repo.time_series_by_agent = AsyncMock(
        return_value=[
            {
                "bucket": "2026-04-04T00:00:00+00:00",
                "agent_name": "investigation",
                "runs": 50,
                "success_rate": 0.94,
                "avg_duration_ms": 4100.0,
                "total_tokens": 200_000,
            },
            {
                "bucket": "2026-04-05T00:00:00+00:00",
                "agent_name": "investigation",
                "runs": 70,
                "success_rate": 0.91,
                "avg_duration_ms": 4300.0,
                "total_tokens": 280_000,
            },
        ]
    )
    return repo


@pytest.fixture(autouse=True)
def _reset_repo():
    """Ensure repo singleton is cleared between tests."""
    original = agent_metrics_api._run_repo
    yield
    agent_metrics_api._run_repo = original


class TestAgentMetricsEndpoint:
    """GET /api/v1/agents/metrics."""

    def test_default_range_is_24h(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["range"] == "24h"
        assert len(data["agents"]) == 2
        assert data["agents"][0]["agent_name"] == "investigation"
        mock_repo.aggregate_by_agent.assert_awaited_once()
        _, kwargs = mock_repo.aggregate_by_agent.call_args
        assert kwargs["range_str"] == "24h"

    def test_custom_range_7d(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics?range=7d")
        assert resp.status_code == 200
        assert resp.json()["range"] == "7d"
        _, kwargs = mock_repo.aggregate_by_agent.call_args
        assert kwargs["range_str"] == "7d"

    def test_invalid_range_rejected(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics?range=bogus")
        assert resp.status_code == 422

    def test_success_rate_is_bounded(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics")
        assert resp.status_code == 200
        for agent in resp.json()["agents"]:
            assert 0.0 <= agent["success_rate"] <= 1.0
            assert agent["total_tokens"] >= 0
            assert agent["estimated_cost_usd"] >= 0.0

    def test_503_when_repo_not_initialized(self):
        client = TestClient(_build_app(None), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics")
        assert resp.status_code == 503


class TestFleetMetricsEndpoint:
    """GET /api/v1/agents/metrics/fleet."""

    def test_fleet_totals(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics/fleet?range=24h")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_agents"] == 2
        assert data["total_runs"] == 160
        assert data["fleet_success_rate"] == 0.925
        mock_repo.aggregate_fleet.assert_awaited_once()

    def test_fleet_default_range(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics/fleet")
        assert resp.status_code == 200
        _, kwargs = mock_repo.aggregate_fleet.call_args
        assert kwargs["range_str"] == "24h"


class TestTrendsEndpoint:
    """GET /api/v1/agents/metrics/trends."""

    def test_trends_7d_uses_day_granularity(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics/trends?range=7d")
        assert resp.status_code == 200
        data = resp.json()
        assert data["range"] == "7d"
        assert data["granularity"] == "day"
        assert len(data["points"]) == 2
        _, kwargs = mock_repo.time_series_by_agent.call_args
        assert kwargs["range_str"] == "7d"
        assert kwargs["agent_name"] is None

    def test_trends_24h_uses_hour_granularity(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics/trends?range=24h")
        assert resp.status_code == 200
        assert resp.json()["granularity"] == "hour"

    def test_trends_filtered_by_agent(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/metrics/trends?range=7d&agent_name=investigation")
        assert resp.status_code == 200
        _, kwargs = mock_repo.time_series_by_agent.call_args
        assert kwargs["agent_name"] == "investigation"

    def test_trends_invalid_range_rejected(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        # 1h is not allowed on the trends endpoint (TrendRange literal).
        resp = client.get("/api/v1/agents/metrics/trends?range=1h")
        assert resp.status_code == 422
