"""Tests for the /api/v1/approvals API endpoints."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.routes.approvals import router
from shieldops.policy.approval_gate import clear_requests

app = FastAPI()
app.include_router(router, prefix="/api/v1")


@pytest.fixture(autouse=True)
def _clean():
    clear_requests()
    yield
    clear_requests()


@pytest.fixture
def client():
    return TestClient(app)


def test_create_approval(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/approvals",
        json={"agent_name": "soc_analyst", "action": "isolate-host"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "pending"
    assert body["agent_name"] == "soc_analyst"
    assert body["id"]


def test_get_approval(client: TestClient) -> None:
    create = client.post(
        "/api/v1/approvals",
        json={"agent_name": "agent-x", "action": "do-thing"},
    )
    req_id = create.json()["id"]
    resp = client.get(f"/api/v1/approvals/{req_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == req_id


def test_get_approval_not_found(client: TestClient) -> None:
    resp = client.get("/api/v1/approvals/nonexistent")
    assert resp.status_code == 404


def test_approve_flow(client: TestClient) -> None:
    create = client.post(
        "/api/v1/approvals",
        json={"agent_name": "agent-x", "action": "do-thing"},
    )
    req_id = create.json()["id"]

    resp = client.post(
        f"/api/v1/approvals/{req_id}/approve",
        json={"approver": "admin@company.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    assert resp.json()["approver"] == "admin@company.com"


def test_deny_flow(client: TestClient) -> None:
    create = client.post(
        "/api/v1/approvals",
        json={"agent_name": "agent-x", "action": "do-thing"},
    )
    req_id = create.json()["id"]

    resp = client.post(
        f"/api/v1/approvals/{req_id}/deny",
        json={"approver": "admin@company.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "denied"


def test_approve_not_found(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/approvals/bogus/approve",
        json={"approver": "admin"},
    )
    assert resp.status_code == 404


def test_deny_not_found(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/approvals/bogus/deny",
        json={"approver": "admin"},
    )
    assert resp.status_code == 404


def test_double_approve_conflict(client: TestClient) -> None:
    create = client.post(
        "/api/v1/approvals",
        json={"agent_name": "agent-x", "action": "do-thing"},
    )
    req_id = create.json()["id"]

    # First approve succeeds
    client.post(f"/api/v1/approvals/{req_id}/approve", json={"approver": "a"})

    # Second approve is a conflict (not pending any more)
    resp = client.post(f"/api/v1/approvals/{req_id}/approve", json={"approver": "b"})
    assert resp.status_code == 409
