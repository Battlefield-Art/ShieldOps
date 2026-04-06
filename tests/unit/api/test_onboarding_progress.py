"""Tests for onboarding progress + SDK health + NL query templates (#213, #235)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.agents.nl_query.templates import (
    SOC_TEMPLATES,
    get_template,
    list_templates,
)
from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.routes import onboarding_progress, sdk_health


@pytest.fixture()
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(onboarding_progress.router)
    a.include_router(sdk_health.router)

    async def _user() -> MagicMock:
        u = MagicMock()
        u.org_id = "test-org"
        u.id = "test-user"
        return u

    a.dependency_overrides[get_current_user] = _user
    return a


@pytest.fixture(autouse=True)
def reset_state() -> None:
    onboarding_progress.reset_progress()


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


class TestOnboardingProgress:
    def test_initial_state(self, client: TestClient) -> None:
        r = client.get("/onboarding/progress")
        assert r.status_code == 200
        data = r.json()
        assert data["current_step"] == "signup"
        assert data["percent_complete"] == 0.0
        assert len(data["steps"]) == 6

    def test_mark_step_complete(self, client: TestClient) -> None:
        r = client.post("/onboarding/progress", json={"step": "signup"})
        assert r.status_code == 200
        data = r.json()
        assert data["current_step"] == "email_verified"
        assert data["percent_complete"] == pytest.approx(16.7, rel=1e-2)

    def test_full_flow(self, client: TestClient) -> None:
        for step in [
            "signup",
            "email_verified",
            "api_key_created",
            "sdk_installed",
            "first_intercept",
            "complete",
        ]:
            r = client.post("/onboarding/progress", json={"step": step})
            assert r.status_code == 200
        final = client.get("/onboarding/progress").json()
        assert final["percent_complete"] == 100.0
        assert all(s["completed"] for s in final["steps"])

    def test_invalid_step(self, client: TestClient) -> None:
        r = client.post("/onboarding/progress", json={"step": "nonsense"})
        assert r.status_code == 400


class TestSDKHealth:
    def test_healthy(self, client: TestClient) -> None:
        r = client.get("/sdk/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["org_id"] == "test-org"
        assert data["api_version"] == "v1"


class TestNLQueryTemplates:
    def test_list_templates(self) -> None:
        templates = list_templates()
        assert len(templates) == len(SOC_TEMPLATES)
        assert all("id" in t and "question" in t for t in templates)

    def test_get_template(self) -> None:
        tpl = get_template("daily_threat_briefing")
        assert tpl is not None
        assert tpl["category"] == "executive"

    def test_get_unknown(self) -> None:
        assert get_template("nonexistent") is None
