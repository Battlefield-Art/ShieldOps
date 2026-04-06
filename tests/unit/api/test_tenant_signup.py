"""Tests for tenant signup + login flow (issue #216)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.routes import tenant_signup


@pytest.fixture(autouse=True)
def _reset_store() -> None:
    tenant_signup.reset_store()
    yield
    tenant_signup.reset_store()


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(tenant_signup.router, prefix="/api/v1")
    return TestClient(app)


def _signup_payload(**overrides: object) -> dict[str, object]:
    return {
        "email": "founder@example.com",
        "org_name": "Acme",
        "password": "correct-horse-battery",
    } | overrides


class TestSignup:
    def test_signup_creates_user_and_org(self, client: TestClient) -> None:
        resp = client.post("/api/v1/signup", json=_signup_payload())
        assert resp.status_code == 201
        body = resp.json()
        assert body["org_id"].startswith("org-")
        assert body["user_id"].startswith("usr-")
        assert body["email"] == "founder@example.com"
        assert body["verification_sent"] is True
        assert body["verification_token"]  # dev token exposed

        store = tenant_signup.get_store()
        assert store.get_user_by_email("founder@example.com") is not None
        assert store.get_org(body["org_id"]) is not None

    def test_signup_rejects_duplicate_email(self, client: TestClient) -> None:
        client.post("/api/v1/signup", json=_signup_payload())
        resp = client.post("/api/v1/signup", json=_signup_payload(org_name="Other"))
        assert resp.status_code == 409

    def test_signup_rejects_short_password(self, client: TestClient) -> None:
        resp = client.post("/api/v1/signup", json=_signup_payload(password="short"))
        assert resp.status_code == 422

    def test_signup_rejects_invalid_email(self, client: TestClient) -> None:
        resp = client.post("/api/v1/signup", json=_signup_payload(email="not-an-email"))
        assert resp.status_code == 422


class TestVerification:
    def test_verify_marks_user_verified(self, client: TestClient) -> None:
        signup = client.post("/api/v1/signup", json=_signup_payload()).json()
        token = signup["verification_token"]

        resp = client.post("/api/v1/signup/verify", json={"token": token})
        assert resp.status_code == 200
        assert resp.json() == {"user_id": signup["user_id"], "email_verified": True}

        store = tenant_signup.get_store()
        user = store.get_user_by_email("founder@example.com")
        assert user is not None and user.email_verified is True

    def test_verify_rejects_unknown_token(self, client: TestClient) -> None:
        resp = client.post("/api/v1/signup/verify", json={"token": "nope"})
        assert resp.status_code == 400

    def test_verify_token_is_single_use(self, client: TestClient) -> None:
        signup = client.post("/api/v1/signup", json=_signup_payload()).json()
        token = signup["verification_token"]
        client.post("/api/v1/signup/verify", json={"token": token})
        again = client.post("/api/v1/signup/verify", json={"token": token})
        assert again.status_code == 400


class TestLogin:
    def test_login_returns_jwt_on_valid_credentials(self, client: TestClient) -> None:
        signup = client.post("/api/v1/signup", json=_signup_payload()).json()

        resp = client.post(
            "/api/v1/signup/login",
            json={"email": "founder@example.com", "password": "correct-horse-battery"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["token_type"] == "bearer"
        assert body["user_id"] == signup["user_id"]
        assert body["org_id"] == signup["org_id"]
        assert body["access_token"].count(".") == 2  # JWT format

    def test_login_rejects_wrong_password(self, client: TestClient) -> None:
        client.post("/api/v1/signup", json=_signup_payload())
        resp = client.post(
            "/api/v1/signup/login",
            json={"email": "founder@example.com", "password": "wrong-password"},
        )
        assert resp.status_code == 401

    def test_login_rejects_unknown_email(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/signup/login",
            json={"email": "ghost@example.com", "password": "whatever-x"},
        )
        assert resp.status_code == 401
