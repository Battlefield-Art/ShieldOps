"""Tests for the Business Value dashboard API.

Covers the two endpoints exposed by ``shieldops.api.routes.business_metrics``:

- ``GET /api/v1/metrics/business``         → 6-KPI snapshot
- ``GET /api/v1/metrics/business/trends``  → single-metric trend series

Repository aggregate calls are stubbed so tests avoid a real database.
Mirrors the fixture pattern used in ``test_agent_metrics_api.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import business_metrics


def _make_user() -> UserResponse:
    return UserResponse(
        id="user-1",
        email="tester@shieldops.ai",
        name="Tester",
        role=UserRole.ADMIN,
        is_active=True,
    )


def _build_app(repo: AsyncMock | None) -> FastAPI:
    """Build a minimal FastAPI app with the business metrics router."""
    business_metrics._run_repo = repo
    app = FastAPI()
    app.include_router(business_metrics.router, prefix="/api/v1")

    async def _override_user() -> UserResponse:
        return _make_user()

    app.dependency_overrides[get_current_user] = _override_user
    return app


@pytest.fixture()
def mock_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.aggregate_fleet = AsyncMock(
        return_value={
            "range": "24h",
            "total_agents": 2,
            "total_runs": 100,
            "total_success": 90,
            "total_failure": 10,
            "fleet_success_rate": 0.9,
            "avg_duration_ms": 5000.0,
            "total_tokens": 500_000,
            "estimated_cost_usd": 4.50,
        }
    )
    repo.time_series_by_agent = AsyncMock(
        return_value=[
            {
                "bucket": "2026-04-04T00:00:00+00:00",
                "agent_name": "investigation",
                "runs": 40,
                "success_rate": 0.9,
                "avg_duration_ms": 4000.0,
                "total_tokens": 200_000,
            },
            {
                "bucket": "2026-04-05T00:00:00+00:00",
                "agent_name": "investigation",
                "runs": 60,
                "success_rate": 0.95,
                "avg_duration_ms": 5000.0,
                "total_tokens": 300_000,
            },
        ]
    )
    return repo


@pytest.fixture()
def empty_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.aggregate_fleet = AsyncMock(return_value={})
    repo.time_series_by_agent = AsyncMock(return_value=[])
    return repo


@pytest.fixture(autouse=True)
def _reset_repo():
    """Clear repo singleton between tests."""
    original = business_metrics._run_repo
    yield
    business_metrics._run_repo = original


class TestBusinessMetricsEndpoint:
    """GET /api/v1/metrics/business."""

    def test_default_range_is_24h(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business")
        assert resp.status_code == 200
        data = resp.json()
        assert data["range"] == "24h"
        # Shape check — every documented KPI must be present.
        expected_keys = {
            "range",
            "mttd_seconds",
            "mttr_seconds",
            "cost_per_incident_usd",
            "risk_score",
            "data_volume_gb",
            "agent_roi_percent",
            "incidents_total",
            "incidents_auto_resolved",
        }
        assert expected_keys.issubset(data.keys())
        mock_repo.aggregate_fleet.assert_awaited_once()
        _, kwargs = mock_repo.aggregate_fleet.call_args
        assert kwargs["range_str"] == "24h"

    def test_custom_range_7d(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business?range=7d")
        assert resp.status_code == 200
        assert resp.json()["range"] == "7d"
        _, kwargs = mock_repo.aggregate_fleet.call_args
        assert kwargs["range_str"] == "7d"

    def test_metrics_are_bounded_and_sane(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business")
        data = resp.json()
        assert 0.0 <= data["risk_score"] <= 100.0
        assert 0.0 <= data["agent_roi_percent"] <= 100.0
        assert data["mttd_seconds"] >= 0.0
        assert data["mttr_seconds"] >= 0.0
        # MTTD should be a fraction of MTTR (detection is fast vs remediation).
        assert data["mttd_seconds"] <= data["mttr_seconds"]
        # 90/100 runs auto-resolved → ROI == 90%.
        assert data["agent_roi_percent"] == pytest.approx(90.0, abs=0.01)
        assert data["incidents_total"] == 100
        assert data["incidents_auto_resolved"] == 90

    def test_empty_data_returns_zeros_not_errors(self, empty_repo: AsyncMock):
        """Fresh tenants with zero runs must get a clean 200 with zeros."""
        client = TestClient(_build_app(empty_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mttd_seconds"] == 0.0
        assert data["mttr_seconds"] == 0.0
        assert data["cost_per_incident_usd"] == 0.0
        assert data["risk_score"] == 0.0
        assert data["data_volume_gb"] == 0.0
        assert data["agent_roi_percent"] == 0.0
        assert data["incidents_total"] == 0
        assert data["incidents_auto_resolved"] == 0

    def test_invalid_range_rejected(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business?range=bogus")
        assert resp.status_code == 422

    def test_503_when_repo_not_initialized(self):
        client = TestClient(_build_app(None), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business")
        assert resp.status_code == 503


class TestBusinessTrendsEndpoint:
    """GET /api/v1/metrics/business/trends."""

    def test_mttr_trend_7d_uses_day_granularity(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?metric=mttr&range=7d")
        assert resp.status_code == 200
        data = resp.json()
        assert data["metric"] == "mttr"
        assert data["range"] == "7d"
        assert data["granularity"] == "day"
        assert len(data["points"]) == 2
        # MTTR = avg_duration_ms / 1000 — first bucket was 4000ms → 4.0s
        assert data["points"][0]["value"] == pytest.approx(4.0, abs=0.01)
        assert data["points"][1]["value"] == pytest.approx(5.0, abs=0.01)

    def test_mttd_trend_is_fraction_of_mttr(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?metric=mttd&range=7d")
        assert resp.status_code == 200
        # MTTD = MTTR * 0.2 → first bucket 4.0 * 0.2 = 0.8
        assert resp.json()["points"][0]["value"] == pytest.approx(0.8, abs=0.01)

    def test_trends_24h_uses_hour_granularity(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?metric=cost&range=24h")
        assert resp.status_code == 200
        assert resp.json()["granularity"] == "hour"

    def test_agent_roi_trend(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?metric=agent_roi&range=7d")
        assert resp.status_code == 200
        points = resp.json()["points"]
        # First bucket: success_rate 0.9 → ROI 90%
        assert points[0]["value"] == pytest.approx(90.0, abs=0.01)
        assert points[1]["value"] == pytest.approx(95.0, abs=0.01)

    def test_trends_empty_data(self, empty_repo: AsyncMock):
        client = TestClient(_build_app(empty_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?metric=mttr&range=7d")
        assert resp.status_code == 200
        assert resp.json()["points"] == []

    def test_metric_is_required(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?range=7d")
        assert resp.status_code == 422

    def test_invalid_metric_rejected(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        resp = client.get("/api/v1/metrics/business/trends?metric=bogus&range=7d")
        assert resp.status_code == 422

    def test_range_filter_propagates(self, mock_repo: AsyncMock):
        client = TestClient(_build_app(mock_repo), raise_server_exceptions=False)
        client.get("/api/v1/metrics/business/trends?metric=mttr&range=30d")
        _, kwargs = mock_repo.time_series_by_agent.call_args
        assert kwargs["range_str"] == "30d"
        assert kwargs["agent_name"] is None
