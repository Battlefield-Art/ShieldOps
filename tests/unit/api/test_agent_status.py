"""Tests for the Agent Status Monitor API (`/api/v1/agents/status`).

Covers:

- ``GET  /api/v1/agents/status``                        — derived list
- ``GET  /api/v1/agents/status/{name}/history``         — recent runs
- ``GET  /api/v1/agents/status/{name}/connectors``      — connector health

Each test builds a fresh FastAPI instance and uses an autouse fixture to
mount the agent_status router BEFORE the legacy ``agents.router`` so that
``/agents/status`` is not shadowed by the ``/agents/{agent_id}`` route in
the real application. ``AgentRunRepository`` is stubbed with ``AsyncMock``
so tests never hit a real database, and the :class:`HealthCheckRegistry`
singleton is reset between tests to keep connector state isolated.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import agent_status
from shieldops.api.routes import agents as legacy_agents
from shieldops.connectors.health import (
    ConnectorHealthStatus,
    ConnectorStatus,
    HealthCheckRegistry,
)
from shieldops.db.models_agent_run import AgentRunStatus


def _make_user() -> UserResponse:
    return UserResponse(
        id="user-1",
        email="tester@shieldops.ai",
        name="Tester",
        role=UserRole.ADMIN,
        is_active=True,
    )


def _run(
    status: str,
    *,
    minutes_ago: int = 0,
    error_message: str | None = None,
    duration_ms: int = 1000,
    run_id: str = "run-x",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=run_id,
        agent_name="investigation",
        status=status,
        duration_ms=duration_ms,
        error_message=error_message,
        created_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
    )


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset router repo + registry singleton between tests."""
    original = agent_status._run_repo
    yield
    agent_status._run_repo = original
    HealthCheckRegistry.reset()


def _build_app(repo: AsyncMock | None) -> FastAPI:
    """Build a minimal FastAPI app with agent_status mounted FIRST.

    The ordering matters: the legacy `agents.router` claims
    `/agents/{agent_id}` which would otherwise match `/agents/status`.
    """
    agent_status._run_repo = repo
    app = FastAPI()
    # Agent status FIRST so /agents/status wins over /agents/{agent_id}
    app.include_router(agent_status.router, prefix="/api/v1")
    app.include_router(legacy_agents.router, prefix="/api/v1")

    async def _override_user() -> UserResponse:
        return _make_user()

    app.dependency_overrides[get_current_user] = _override_user
    return app


# ── /agents/status list endpoint ────────────────────────────────────


class TestAgentStatusList:
    def test_empty_repo_returns_all_idle(self):
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=([], 0))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)

        resp = client.get("/api/v1/agents/status")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["agents"]) == 10
        for item in data["agents"]:
            assert item["status"] == "idle"
            assert item["last_run"] is None
            assert item["total_runs"] == 0
            assert item["success_rate"] == 0.0
            assert item["recent_errors"] == []

        # Ensure every launch agent is returned (set equality).
        assert {a["agent_name"] for a in data["agents"]} == set(agent_status.LAUNCH_AGENTS)

    def test_healthy_when_latest_completed(self):
        runs = [
            _run(AgentRunStatus.COMPLETED, minutes_ago=1),
            _run(AgentRunStatus.COMPLETED, minutes_ago=30),
            _run(AgentRunStatus.FAILED, minutes_ago=120, error_message="old boom"),
        ]
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=(runs, 3))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)

        resp = client.get("/api/v1/agents/status")
        assert resp.status_code == 200
        first = resp.json()["agents"][0]
        assert first["status"] == "healthy"
        assert first["total_runs"] == 3
        # 2 of 3 terminal runs succeeded → 2/3
        assert first["success_rate"] == pytest.approx(0.6667, rel=1e-3)
        assert first["recent_errors"] == ["old boom"]

    def test_running_when_latest_three_contain_running(self):
        runs = [
            _run(AgentRunStatus.RUNNING, minutes_ago=0),
            _run(AgentRunStatus.COMPLETED, minutes_ago=5),
            _run(AgentRunStatus.COMPLETED, minutes_ago=10),
        ]
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=(runs, 3))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)

        resp = client.get("/api/v1/agents/status")
        assert resp.status_code == 200
        assert resp.json()["agents"][0]["status"] == "running"

    def test_error_when_latest_failed(self):
        runs = [
            _run(AgentRunStatus.FAILED, minutes_ago=1, error_message="connection refused"),
            _run(AgentRunStatus.COMPLETED, minutes_ago=5),
        ]
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=(runs, 2))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)

        resp = client.get("/api/v1/agents/status")
        assert resp.status_code == 200
        first = resp.json()["agents"][0]
        assert first["status"] == "error"
        assert "connection refused" in first["recent_errors"]

    def test_503_when_repo_not_initialized(self):
        client = TestClient(_build_app(None), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/status")
        assert resp.status_code == 503


# ── /agents/status/{name}/history ───────────────────────────────────


class TestAgentHistory:
    def test_happy_path(self):
        runs = [
            _run(AgentRunStatus.COMPLETED, run_id="run-1", minutes_ago=1),
            _run(AgentRunStatus.FAILED, run_id="run-2", minutes_ago=5, error_message="bad"),
        ]
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=(runs, 2))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)

        resp = client.get("/api/v1/agents/status/investigation/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_name"] == "investigation"
        assert len(data["runs"]) == 2
        assert data["runs"][0]["id"] == "run-1"
        assert data["runs"][1]["error_message"] == "bad"
        _, kwargs = repo.list_runs.call_args
        assert kwargs["agent_name"] == "investigation"
        assert kwargs["limit"] == 10

    def test_unknown_agent_returns_404(self):
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=([], 0))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)

        resp = client.get("/api/v1/agents/status/not_a_real_agent/history")
        assert resp.status_code == 404
        repo.list_runs.assert_not_called()


# ── /agents/status/{name}/connectors ────────────────────────────────


class _StubConnector:
    def __init__(self, status: ConnectorStatus, message: str = "ok") -> None:
        self._status = status
        self._message = message

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            status=self._status,
            latency_ms=12.5,
            message=self._message,
        )


class TestAgentConnectors:
    def test_returns_live_health(self):
        repo = AsyncMock()
        registry = HealthCheckRegistry()
        registry.register("aws", _StubConnector(ConnectorStatus.HEALTHY, "sts ok"))
        registry.register("splunk", _StubConnector(ConnectorStatus.DEGRADED, "slow response"))
        # datadog intentionally not registered → reported as "unknown"

        client = TestClient(_build_app(repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/status/investigation/connectors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_name"] == "investigation"
        by_name = {c["name"]: c for c in data["connectors"]}
        assert by_name["aws"]["status"] == "healthy"
        assert by_name["aws"]["message"] == "sts ok"
        assert by_name["splunk"]["status"] == "degraded"
        assert by_name["datadog"]["status"] == "unknown"

    def test_unknown_agent_returns_404(self):
        repo = AsyncMock()
        client = TestClient(_build_app(repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/status/nope/connectors")
        assert resp.status_code == 404


# ── Router ordering sanity check ────────────────────────────────────


class TestRouterOrdering:
    """Regression: `/agents/status` must not be shadowed by `/agents/{id}`."""

    def test_status_path_not_shadowed(self):
        repo = AsyncMock()
        repo.list_runs = AsyncMock(return_value=([], 0))
        client = TestClient(_build_app(repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/agents/status")
        # A 200 (not 404/422 from the legacy /agents/{agent_id} handler)
        # proves the agent_status router was matched first.
        assert resp.status_code == 200
        assert "agents" in resp.json()
