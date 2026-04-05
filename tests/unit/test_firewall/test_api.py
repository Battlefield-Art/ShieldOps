"""Tests for the firewall policies API routes."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes.firewall_policies import (
    router,
    set_evaluator,
)
from shieldops.firewall.evaluator import PolicyEvaluator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MOCK_USER = UserResponse(
    id="user-1",
    email="alice@acme.com",
    name="Alice",
    role=UserRole.ADMIN,
    is_active=True,
)


def _override_current_user() -> UserResponse:
    return _MOCK_USER


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")

    # Override auth dependency
    from shieldops.api.auth.dependencies import get_current_user

    test_app.dependency_overrides[get_current_user] = _override_current_user

    # Fresh evaluator per test
    set_evaluator(PolicyEvaluator())
    yield test_app
    set_evaluator(None)  # type: ignore[arg-type]


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# CRUD tests
# ---------------------------------------------------------------------------


class TestCreatePolicy:
    def test_create_returns_201(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/firewall/policies",
            json={
                "name": "block-prod-deletes",
                "description": "Block deletes in prod",
                "condition": {"tool_name_pattern": "delete_*"},
                "action": "deny",
                "priority": 5,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "block-prod-deletes"
        assert data["action"] == "deny"
        assert data["org_id"] == _MOCK_USER.id  # falls back to user.id

    def test_create_default_values(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/firewall/policies",
            json={"name": "minimal"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["action"] == "allow"
        assert data["priority"] == 100
        assert data["enabled"] is True


class TestListPolicies:
    def test_list_empty(self, client: TestClient) -> None:
        resp = client.get("/api/v1/firewall/policies")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_after_create(self, client: TestClient) -> None:
        client.post("/api/v1/firewall/policies", json={"name": "rule1"})
        client.post("/api/v1/firewall/policies", json={"name": "rule2"})
        resp = client.get("/api/v1/firewall/policies")
        assert resp.status_code == 200
        assert len(resp.json()) == 2


class TestGetPolicy:
    def test_get_existing(self, client: TestClient) -> None:
        create_resp = client.post("/api/v1/firewall/policies", json={"name": "my-rule"})
        rule_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/firewall/policies/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "my-rule"

    def test_get_nonexistent(self, client: TestClient) -> None:
        resp = client.get("/api/v1/firewall/policies/nonexistent-id")
        assert resp.status_code == 404


class TestUpdatePolicy:
    def test_update_existing(self, client: TestClient) -> None:
        create_resp = client.post(
            "/api/v1/firewall/policies", json={"name": "old-name", "priority": 50}
        )
        rule_id = create_resp.json()["id"]
        resp = client.put(
            f"/api/v1/firewall/policies/{rule_id}",
            json={"name": "new-name", "priority": 10},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "new-name"
        assert resp.json()["priority"] == 10

    def test_update_nonexistent(self, client: TestClient) -> None:
        resp = client.put(
            "/api/v1/firewall/policies/no-such-id",
            json={"name": "x"},
        )
        assert resp.status_code == 404


class TestDeletePolicy:
    def test_delete_existing(self, client: TestClient) -> None:
        create_resp = client.post("/api/v1/firewall/policies", json={"name": "doomed"})
        rule_id = create_resp.json()["id"]
        resp = client.delete(f"/api/v1/firewall/policies/{rule_id}")
        assert resp.status_code == 204

        # Confirm gone
        resp2 = client.get(f"/api/v1/firewall/policies/{rule_id}")
        assert resp2.status_code == 404

    def test_delete_nonexistent(self, client: TestClient) -> None:
        resp = client.delete("/api/v1/firewall/policies/no-such-id")
        assert resp.status_code == 404


class TestListDefaults:
    def test_defaults_endpoint(self, client: TestClient) -> None:
        resp = client.get("/api/v1/firewall/policies/defaults")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        names = [r["name"] for r in data]
        assert any("delete_database" in n.lower() for n in names)


class TestEvaluateEndpoint:
    def test_evaluate_deny_dangerous(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/firewall/policies/evaluate",
            json={"tool_name": "delete_database"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["risk_score"] > 0.5

    def test_evaluate_allow_read(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/firewall/policies/evaluate",
            json={"tool_name": "read_logs"},
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"

    def test_evaluate_review(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/firewall/policies/evaluate",
            json={"tool_name": "create_user"},
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "review"

    def test_evaluate_with_custom_rule(self, client: TestClient) -> None:
        # Create a custom deny rule for the org
        client.post(
            "/api/v1/firewall/policies",
            json={
                "name": "deny-custom",
                "condition": {"tool_name_pattern": "my_tool"},
                "action": "deny",
                "priority": 0,
            },
        )
        resp = client.post(
            "/api/v1/firewall/policies/evaluate",
            json={"tool_name": "my_tool"},
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "deny"
