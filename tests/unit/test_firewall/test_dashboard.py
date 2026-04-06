"""Tests for the Agent Firewall dashboard endpoints.

Tests cover:
- GET /firewall/dashboard/stats — correct counts after evaluations
- GET /firewall/dashboard/stream — paginated recent evaluations
- Org-scoping via JWT auth
- Empty state returns zeros
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import firewall_dashboard


def _create_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(firewall_dashboard.router, prefix="/api/v1")
    return app


def _mock_user() -> UserResponse:
    return UserResponse(
        id="org-test-1",
        email="analyst@test.com",
        name="Analyst",
        role=UserRole.ADMIN,
        is_active=True,
    )


@pytest.fixture(autouse=True)
def _reset_counters():
    """Reset in-memory counters between tests."""
    firewall_dashboard.reset_counters()
    yield
    firewall_dashboard.reset_counters()


@pytest.fixture
def client():
    app = _create_test_app()
    app.dependency_overrides[get_current_user] = _mock_user
    return TestClient(app)


class TestStatsEndpoint:
    """GET /api/v1/firewall/dashboard/stats."""

    def test_empty_stats(self, client: TestClient) -> None:
        resp = client.get("/api/v1/firewall/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_evaluations"] == 0
        assert data["blocked_count"] == 0
        assert data["allowed_count"] == 0
        assert data["review_count"] == 0
        assert data["top_risky_tools"] == []
        assert data["evaluations_per_hour"] == {}

    def test_stats_after_evaluations(self, client: TestClient) -> None:
        org = "org-test-1"
        firewall_dashboard.record_evaluation(org, "read_logs", "allow", 0.1)
        firewall_dashboard.record_evaluation(org, "read_logs", "allow", 0.15)
        firewall_dashboard.record_evaluation(org, "delete_database", "deny", 1.0)
        firewall_dashboard.record_evaluation(org, "create_user", "review", 0.6)

        resp = client.get("/api/v1/firewall/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_evaluations"] == 4
        assert data["blocked_count"] == 1
        assert data["allowed_count"] == 2
        assert data["review_count"] == 1

        # Top risky tools should include both tools, delete_database first
        tools = data["top_risky_tools"]
        assert len(tools) == 3
        assert tools[0]["tool_name"] == "delete_database"
        assert tools[0]["avg_risk"] == 1.0
        assert tools[0]["count"] == 1

    def test_stats_org_scoped(self, client: TestClient) -> None:
        """Stats from another org should not appear."""
        firewall_dashboard.record_evaluation("other-org", "read_logs", "allow", 0.1)
        firewall_dashboard.record_evaluation("org-test-1", "write_file", "allow", 0.2)

        resp = client.get("/api/v1/firewall/dashboard/stats")
        data = resp.json()
        assert data["total_evaluations"] == 1
        assert data["top_risky_tools"][0]["tool_name"] == "write_file"

    def test_evaluations_per_hour(self, client: TestClient) -> None:
        firewall_dashboard.record_evaluation("org-test-1", "read_logs", "allow", 0.1)

        resp = client.get("/api/v1/firewall/dashboard/stats")
        data = resp.json()
        assert len(data["evaluations_per_hour"]) == 1
        # The single hour bucket should have count 1
        assert list(data["evaluations_per_hour"].values()) == [1]


class TestStreamEndpoint:
    """GET /api/v1/firewall/dashboard/stream."""

    def test_empty_stream(self, client: TestClient) -> None:
        resp = client.get("/api/v1/firewall/dashboard/stream")
        assert resp.status_code == 200
        data = resp.json()
        assert data["evaluations"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    def test_stream_returns_recent(self, client: TestClient) -> None:
        org = "org-test-1"
        for i in range(5):
            firewall_dashboard.record_evaluation(org, f"tool_{i}", "allow", round(i * 0.1, 1))

        resp = client.get("/api/v1/firewall/dashboard/stream")
        data = resp.json()
        assert data["total"] == 5
        assert len(data["evaluations"]) == 5
        # Newest first
        assert data["evaluations"][0]["tool_name"] == "tool_4"
        assert data["evaluations"][-1]["tool_name"] == "tool_0"

    def test_stream_pagination(self, client: TestClient) -> None:
        org = "org-test-1"
        for i in range(10):
            firewall_dashboard.record_evaluation(org, f"tool_{i}", "allow", 0.1)

        resp = client.get("/api/v1/firewall/dashboard/stream?page=1&limit=3")
        data = resp.json()
        assert len(data["evaluations"]) == 3
        assert data["total"] == 10
        assert data["page"] == 1
        assert data["limit"] == 3
        # First page = newest 3
        assert data["evaluations"][0]["tool_name"] == "tool_9"

        resp2 = client.get("/api/v1/firewall/dashboard/stream?page=2&limit=3")
        data2 = resp2.json()
        assert len(data2["evaluations"]) == 3
        assert data2["evaluations"][0]["tool_name"] == "tool_6"

    def test_stream_org_scoped(self, client: TestClient) -> None:
        firewall_dashboard.record_evaluation("other-org", "tool_x", "allow", 0.1)
        firewall_dashboard.record_evaluation("org-test-1", "tool_y", "deny", 0.9)

        resp = client.get("/api/v1/firewall/dashboard/stream")
        data = resp.json()
        assert data["total"] == 1
        assert data["evaluations"][0]["tool_name"] == "tool_y"
