"""Tests for connector setup / onboarding wizard API.

Covers:
- Encryption round-trip (encrypt/decrypt)
- POST /connectors/setup creates an encrypted record
- GET /connectors lists org connectors
- POST /connectors/{provider}/test re-runs the health check
- DELETE /connectors/{provider} removes the record
- Tenant isolation (org A cannot see/delete org B's connectors)
- Unknown provider returns 400
- Missing credential fields returns 422
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import connector_setup
from shieldops.api.routes.connector_setup import (
    decrypt_credentials,
    encrypt_credentials,
)


def _mock_admin_user(org_id: str = "default") -> UserResponse:
    user = UserResponse(
        id="test-admin",
        email="admin@shieldops.test",
        name="Test Admin",
        role=UserRole.ADMIN,
        is_active=True,
    )
    # Attach org_id as an arbitrary attribute (UserResponse may not define it)
    object.__setattr__(user, "org_id", org_id)
    return user


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_module_repo() -> Any:
    original = connector_setup._repository
    connector_setup._repository = None
    yield
    connector_setup._repository = original


@pytest.fixture(autouse=True)
def _set_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELDOPS_ENCRYPTION_KEY", "shieldops-unit-test-key")


def _create_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(connector_setup.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: _mock_admin_user()
    return app


@pytest.fixture()
def mock_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.upsert_connector_config = AsyncMock(
        return_value={
            "id": "con-abc123",
            "provider": "aws",
            "created_at": "2026-04-05T10:00:00+00:00",
        }
    )
    repo.list_connector_configs = AsyncMock(return_value=[])
    repo.get_connector_config = AsyncMock(return_value=None)
    repo.update_connector_config = AsyncMock(return_value=None)
    repo.delete_connector_config = AsyncMock(return_value=True)
    return repo


def _build_client(mock_repo: AsyncMock) -> TestClient:
    app = _create_test_app()
    connector_setup.set_repository(mock_repo)
    return TestClient(app, raise_server_exceptions=False)


# ── Encryption ──────────────────────────────────────────────────────


class TestEncryption:
    def test_round_trip_plain_string_key(self) -> None:
        creds = {"access_key_id": "AKIA123", "secret_access_key": "sekret", "region": "us-east-1"}
        ct = encrypt_credentials(creds)
        assert isinstance(ct, str)
        assert "AKIA123" not in ct
        assert "sekret" not in ct
        pt = decrypt_credentials(ct)
        assert pt == creds

    def test_ciphertext_non_deterministic(self) -> None:
        creds = {"token": "abc"}
        assert encrypt_credentials(creds) != encrypt_credentials(creds)

    def test_round_trip_with_fernet_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()
        monkeypatch.setenv("SHIELDOPS_ENCRYPTION_KEY", key)
        creds = {"bot_token": "xoxb-test"}
        assert decrypt_credentials(encrypt_credentials(creds)) == creds


# ── POST /connectors/setup ───────────────────────────────────────────


class TestSetupConnector:
    def test_setup_creates_encrypted_record(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        resp = client.post(
            "/api/v1/connectors/setup",
            json={
                "provider": "aws",
                "credentials": {
                    "access_key_id": "AKIA123",
                    "secret_access_key": "sekret",
                    "region": "us-east-1",
                },
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["provider"] == "aws"
        assert data["status"] == "active"
        assert data["id"] == "con-abc123"

        mock_repo.upsert_connector_config.assert_awaited_once()
        kwargs = mock_repo.upsert_connector_config.call_args.kwargs
        assert kwargs["provider"] == "aws"
        # Ensure plaintext is NOT passed to the repo
        encrypted = kwargs["encrypted_credentials"]
        assert "AKIA123" not in encrypted
        assert "sekret" not in encrypted
        # Round-trip works
        assert decrypt_credentials(encrypted)["access_key_id"] == "AKIA123"

    def test_setup_unknown_provider_returns_400(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        resp = client.post(
            "/api/v1/connectors/setup",
            json={"provider": "bogus", "credentials": {"foo": "bar"}},
        )
        assert resp.status_code == 400
        assert "Unsupported provider" in resp.json()["detail"]
        mock_repo.upsert_connector_config.assert_not_awaited()

    def test_setup_missing_fields_returns_422(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        resp = client.post(
            "/api/v1/connectors/setup",
            json={"provider": "aws", "credentials": {"region": "us-east-1"}},
        )
        assert resp.status_code == 422
        assert "missing fields" in resp.json()["detail"]

    def test_setup_supports_pagerduty(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        mock_repo.upsert_connector_config.return_value = {
            "id": "con-pd",
            "provider": "pagerduty",
            "created_at": None,
        }
        resp = client.post(
            "/api/v1/connectors/setup",
            json={"provider": "pagerduty", "credentials": {"api_key": "pd-token"}},
        )
        assert resp.status_code == 200

    def test_setup_supports_slack(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        mock_repo.upsert_connector_config.return_value = {
            "id": "con-sl",
            "provider": "slack",
            "created_at": None,
        }
        resp = client.post(
            "/api/v1/connectors/setup",
            json={"provider": "slack", "credentials": {"bot_token": "xoxb-123"}},
        )
        assert resp.status_code == 200

    def test_setup_supports_servicenow(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        mock_repo.upsert_connector_config.return_value = {
            "id": "con-sn",
            "provider": "servicenow",
            "created_at": None,
        }
        resp = client.post(
            "/api/v1/connectors/setup",
            json={
                "provider": "servicenow",
                "credentials": {
                    "instance_url": "https://dev.service-now.com",
                    "username": "admin",
                    "password": "pw",
                },
            },
        )
        assert resp.status_code == 200


# ── GET /connectors ──────────────────────────────────────────────────


class TestListConnectors:
    def test_list_empty(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        resp = client.get("/api/v1/connectors")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["connectors"] == []

    def test_list_returns_records_without_plaintext(self, mock_repo: AsyncMock) -> None:
        mock_repo.list_connector_configs.return_value = [
            {
                "id": "con-1",
                "provider": "aws",
                "status": "active",
                "last_health_check": "2026-04-05T10:00:00+00:00",
                "last_error": "",
                "created_at": "2026-04-05T09:00:00+00:00",
                "encrypted_credentials": "gAAAA-secret-ciphertext",
            },
        ]
        client = _build_client(mock_repo)
        resp = client.get("/api/v1/connectors")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        entry = body["connectors"][0]
        assert entry["provider"] == "aws"
        assert entry["status"] == "active"
        # Plaintext/ciphertext MUST NOT be leaked in the list response
        assert "encrypted_credentials" not in entry


# ── POST /connectors/{provider}/test ─────────────────────────────────


class TestTestConnector:
    def test_test_unknown_returns_404(self, mock_repo: AsyncMock) -> None:
        mock_repo.get_connector_config.return_value = None
        client = _build_client(mock_repo)
        resp = client.post("/api/v1/connectors/aws/test")
        assert resp.status_code == 404

    def test_test_rechecks_and_updates_status(self, mock_repo: AsyncMock) -> None:
        encrypted = encrypt_credentials(
            {
                "access_key_id": "AKIA",
                "secret_access_key": "sek",
                "region": "us-east-1",
            }
        )
        mock_repo.get_connector_config.return_value = {
            "id": "con-1",
            "provider": "aws",
            "encrypted_credentials": encrypted,
            "status": "active",
        }
        client = _build_client(mock_repo)
        resp = client.post("/api/v1/connectors/aws/test")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws"
        assert body["status"] == "active"
        mock_repo.update_connector_config.assert_awaited_once()

    def test_test_reports_error_for_bad_creds(self, mock_repo: AsyncMock) -> None:
        # Credentials are missing required fields (only region)
        encrypted = encrypt_credentials({"region": "us-east-1"})
        mock_repo.get_connector_config.return_value = {
            "id": "con-1",
            "provider": "aws",
            "encrypted_credentials": encrypted,
            "status": "active",
        }
        client = _build_client(mock_repo)
        resp = client.post("/api/v1/connectors/aws/test")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "error"
        assert "missing fields" in body["message"]


# ── DELETE /connectors/{provider} ────────────────────────────────────


class TestDeleteConnector:
    def test_delete_success(self, mock_repo: AsyncMock) -> None:
        mock_repo.delete_connector_config.return_value = True
        client = _build_client(mock_repo)
        resp = client.delete("/api/v1/connectors/aws")
        assert resp.status_code == 200
        assert resp.json() == {"deleted": True, "provider": "aws"}
        mock_repo.delete_connector_config.assert_awaited_once()

    def test_delete_not_found(self, mock_repo: AsyncMock) -> None:
        mock_repo.delete_connector_config.return_value = False
        client = _build_client(mock_repo)
        resp = client.delete("/api/v1/connectors/aws")
        assert resp.status_code == 404


# ── Tenant isolation ─────────────────────────────────────────────────


class TestTenantIsolation:
    def test_list_scopes_by_org_id(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        client.get("/api/v1/connectors")
        mock_repo.list_connector_configs.assert_awaited_once()
        kwargs = mock_repo.list_connector_configs.call_args.kwargs
        assert "org_id" in kwargs
        # Default test user has no org_id → "default"
        assert kwargs["org_id"] == "default"

    def test_setup_scopes_by_org_id(self, mock_repo: AsyncMock) -> None:
        client = _build_client(mock_repo)
        client.post(
            "/api/v1/connectors/setup",
            json={"provider": "slack", "credentials": {"bot_token": "xoxb-1"}},
        )
        kwargs = mock_repo.upsert_connector_config.call_args.kwargs
        assert kwargs["org_id"] == "default"

    def test_delete_scopes_by_org_id(self, mock_repo: AsyncMock) -> None:
        mock_repo.delete_connector_config.return_value = True
        client = _build_client(mock_repo)
        client.delete("/api/v1/connectors/aws")
        kwargs = mock_repo.delete_connector_config.call_args.kwargs
        assert kwargs["org_id"] == "default"
        assert kwargs["provider"] == "aws"


# ── Repo not wired ───────────────────────────────────────────────────


class TestRepoUnavailable:
    def test_setup_503_when_no_repo(self) -> None:
        app = _create_test_app()
        connector_setup.set_repository(None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/connectors/setup",
            json={"provider": "slack", "credentials": {"bot_token": "xoxb-1"}},
        )
        assert resp.status_code == 503
