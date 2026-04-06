"""Tests for Executive/SOC Manager/CISO dashboard APIs + ROI Calculator (#236, #237, #238, #239)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.routes import (
    ciso_dashboard,
    executive_dashboard,
    roi_calculator,
    soc_manager_dashboard,
)


@pytest.fixture()
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(executive_dashboard.router)
    a.include_router(soc_manager_dashboard.router)
    a.include_router(ciso_dashboard.router)
    a.include_router(roi_calculator.router)

    async def _user() -> MagicMock:
        u = MagicMock()
        u.org_id = "test-org"
        u.id = "test-user"
        return u

    a.dependency_overrides[get_current_user] = _user
    return a


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


class TestExecutiveDashboard:
    def test_get_metrics(self, client: TestClient) -> None:
        r = client.get("/dashboards/executive?range=7d")
        assert r.status_code == 200
        data = r.json()
        assert 0 <= data["risk_posture_score"] <= 100
        assert 0 <= data["agent_roi_percent"] <= 100
        assert "HIPAA" in data["compliance"]
        assert data["range"] == "7d"

    def test_invalid_range(self, client: TestClient) -> None:
        r = client.get("/dashboards/executive?range=invalid")
        assert r.status_code == 422

    def test_trends(self, client: TestClient) -> None:
        r = client.get("/dashboards/executive/trends?metric=risk&range=7d")
        assert r.status_code == 200
        assert r.json()["metric"] == "risk"
        assert len(r.json()["points"]) == 7


class TestSOCManagerDashboard:
    def test_get_metrics(self, client: TestClient) -> None:
        r = client.get("/dashboards/soc-manager")
        assert r.status_code == 200
        data = r.json()
        assert data["mttd_seconds"] >= 0
        assert data["mttr_seconds"] >= 0
        assert "critical" in data["alert_volume_by_severity"]
        assert "investigation" in data["agent_effectiveness"]

    def test_trends(self, client: TestClient) -> None:
        r = client.get("/dashboards/soc-manager/trends?metric=mttd&range=7d")
        assert r.status_code == 200
        assert len(r.json()["points"]) == 7


class TestCISODashboard:
    def test_get_metrics(self, client: TestClient) -> None:
        r = client.get("/dashboards/ciso")
        assert r.status_code == 200
        data = r.json()
        assert len(data["mitre_heatmap"]) > 0
        assert all("technique_id" in t for t in data["mitre_heatmap"])
        assert "HIPAA" in data["audit_readiness"]

    def test_drill_down(self, client: TestClient) -> None:
        r = client.get("/dashboards/ciso/mitre/T1078/findings")
        assert r.status_code == 200
        assert r.json()["technique_id"] == "T1078"


class TestROICalculator:
    def test_basic_calculation(self, client: TestClient) -> None:
        r = client.post(
            "/tools/roi-calculator",
            json={
                "current_siem_cost_usd": 500_000,
                "daily_log_volume_gb": 100,
                "soc_team_size": 5,
                "avg_ir_time_min": 60,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["breakdown"]["total_annual_savings"] > 0
        assert data["three_year_savings"] > data["breakdown"]["total_annual_savings"]
        assert "ShieldOps saves" in data["shareable_summary"]

    def test_high_volume(self, client: TestClient) -> None:
        r = client.post(
            "/tools/roi-calculator",
            json={
                "current_siem_cost_usd": 2_000_000,
                "daily_log_volume_gb": 500,
                "soc_team_size": 20,
                "avg_ir_time_min": 45,
                "automation_rate": 0.80,
            },
        )
        assert r.status_code == 200
        assert r.json()["breakdown"]["siem_savings_annual"] > 0

    def test_invalid_input(self, client: TestClient) -> None:
        r = client.post(
            "/tools/roi-calculator",
            json={
                "current_siem_cost_usd": -100,
                "daily_log_volume_gb": 10,
                "soc_team_size": 1,
                "avg_ir_time_min": 30,
            },
        )
        assert r.status_code == 422
