"""Tests for data ingestion API endpoints.

Tests cover:
- POST /ingest/events with valid batch -> 202 + event_ids
- POST /ingest/events with empty batch -> 202 + accepted=0
- POST /ingest/events with invalid event (missing source) -> partial acceptance
- GET /ingest/health -> buffer status
- GET /ingest/stats -> statistics
- Auth required on all protected endpoints
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.routes import ingest


def _create_test_app() -> FastAPI:
    """Create a minimal FastAPI app with the ingest router."""
    app = FastAPI()
    app.include_router(ingest.router, prefix="/api/v1")
    return app


def _mock_user() -> UserResponse:
    return UserResponse(
        id="user-1",
        email="analyst@test.com",
        name="Analyst",
        role=UserRole.OPERATOR,
        is_active=True,
    )


@pytest.fixture(autouse=True)
def _reset_module_state():
    """Reset module-level state between tests."""
    ingest._event_buffer.clear()
    ingest._stats.update({"total_accepted": 0, "total_rejected": 0, "total_requests": 0})
    ingest._source_counts.clear()
    yield
    ingest._event_buffer.clear()
    ingest._stats.update({"total_accepted": 0, "total_rejected": 0, "total_requests": 0})
    ingest._source_counts.clear()


@pytest.fixture
def client() -> TestClient:
    """TestClient with auth bypassed."""
    app = _create_test_app()

    async def _mock() -> UserResponse:
        return _mock_user()

    app.dependency_overrides[get_current_user] = _mock
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def unauthed_client() -> TestClient:
    """TestClient without auth override — should fail on protected routes."""
    app = _create_test_app()
    return TestClient(app, raise_server_exceptions=False)


def _valid_event(**overrides: Any) -> dict[str, Any]:
    """Generate a valid event payload."""
    base: dict[str, Any] = {
        "source": "cloudtrail",
        "event_type": "api_activity",
        "timestamp": "2026-04-04T12:00:00Z",
        "raw_event": {"action": "AssumeRole", "principal": "arn:aws:iam::123:role/test"},
        "metadata": {"region": "us-east-1"},
    }
    base.update(overrides)
    return base


# ================================================================
# POST /ingest/events
# ================================================================


class TestIngestEvents:
    """Tests for POST /api/v1/ingest/events."""

    def test_valid_batch_returns_202(self, client: TestClient) -> None:
        """Valid batch -> 202 with event_ids."""
        resp = client.post(
            "/api/v1/ingest/events",
            json={"events": [_valid_event(), _valid_event(source="syslog")]},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 2
        assert data["rejected"] == 0
        assert len(data["event_ids"]) == 2
        assert data["errors"] == []

    def test_empty_batch_returns_202(self, client: TestClient) -> None:
        """Empty batch -> 202 with accepted=0."""
        resp = client.post("/api/v1/ingest/events", json={"events": []})
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 0
        assert data["rejected"] == 0
        assert data["event_ids"] == []

    def test_invalid_event_partial_acceptance(self, client: TestClient) -> None:
        """Mix of valid and invalid events -> partial acceptance."""
        events = [
            _valid_event(),
            # Missing source and empty raw_event
            {"source": "", "raw_event": {}, "event_type": "bad"},
            _valid_event(source="webhook"),
        ]
        resp = client.post("/api/v1/ingest/events", json={"events": events})
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 2
        assert data["rejected"] == 1
        assert len(data["event_ids"]) == 2
        assert len(data["errors"]) == 1
        assert "event[1]" in data["errors"][0]

    def test_invalid_source_rejected(self, client: TestClient) -> None:
        """Event with invalid source value is rejected."""
        resp = client.post(
            "/api/v1/ingest/events",
            json={"events": [_valid_event(source="unknown_src")]},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["rejected"] == 1
        assert data["accepted"] == 0
        assert "invalid source" in data["errors"][0]

    def test_batch_source_override(self, client: TestClient) -> None:
        """Batch-level source overrides event source when event source is empty."""
        events = [{"source": "", "raw_event": {"foo": "bar"}, "event_type": "test"}]
        resp = client.post(
            "/api/v1/ingest/events",
            json={"events": events, "source": "crowdstrike_fdr"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 1

    def test_invalid_timestamp_rejected(self, client: TestClient) -> None:
        """Event with unparseable timestamp is rejected."""
        resp = client.post(
            "/api/v1/ingest/events",
            json={"events": [_valid_event(timestamp="not-a-date")]},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["rejected"] == 1
        assert "ISO 8601" in data["errors"][0]

    def test_buffer_eviction(self, client: TestClient) -> None:
        """When buffer is full, oldest events are evicted."""
        ingest._MAX_BUFFER = 3  # temporarily shrink for test
        try:
            events = [_valid_event() for _ in range(5)]
            resp = client.post("/api/v1/ingest/events", json={"events": events})
            assert resp.status_code == 202
            assert resp.json()["accepted"] == 5
            # Buffer should have been capped at 3
            assert len(ingest._event_buffer) == 3
        finally:
            ingest._MAX_BUFFER = 100_000

    def test_extra_fields_rejected(self, client: TestClient) -> None:
        """Extra fields in the batch request body should be rejected (extra=forbid)."""
        resp = client.post(
            "/api/v1/ingest/events",
            json={"events": [], "rogue_field": "oops"},
        )
        assert resp.status_code == 422


# ================================================================
# GET /ingest/health
# ================================================================


class TestIngestHealth:
    """Tests for GET /api/v1/ingest/health."""

    def test_health_returns_status(self, client: TestClient) -> None:
        """Health endpoint returns buffer info."""
        resp = client.get("/api/v1/ingest/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "buffer_size" in data
        assert "buffer_capacity" in data
        assert "timestamp" in data

    def test_health_no_auth_required(self, unauthed_client: TestClient) -> None:
        """Health endpoint is accessible without auth."""
        resp = unauthed_client.get("/api/v1/ingest/health")
        assert resp.status_code == 200


# ================================================================
# GET /ingest/stats
# ================================================================


class TestIngestStats:
    """Tests for GET /api/v1/ingest/stats."""

    def test_stats_after_ingestion(self, client: TestClient) -> None:
        """Stats reflect ingestion activity."""
        # Ingest some events first
        client.post(
            "/api/v1/ingest/events",
            json={"events": [_valid_event(), _valid_event(source="syslog")]},
        )
        resp = client.get("/api/v1/ingest/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 1
        assert data["total_accepted"] == 2
        assert data["total_rejected"] == 0
        assert data["buffer_size"] == 2
        assert data["source_counts"]["cloudtrail"] == 1
        assert data["source_counts"]["syslog"] == 1

    def test_stats_empty(self, client: TestClient) -> None:
        """Stats with no ingestion."""
        resp = client.get("/api/v1/ingest/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_accepted"] == 0
        assert data["buffer_size"] == 0

    def test_stats_requires_auth(self, unauthed_client: TestClient) -> None:
        """Stats endpoint requires authentication."""
        resp = unauthed_client.get("/api/v1/ingest/stats")
        # Without auth, should get 403 or 401
        assert resp.status_code in (401, 403)


# ================================================================
# Auth enforcement
# ================================================================


class TestIngestAuth:
    """Auth enforcement on ingestion endpoints."""

    def test_events_requires_auth(self, unauthed_client: TestClient) -> None:
        """POST /ingest/events requires auth."""
        resp = unauthed_client.post(
            "/api/v1/ingest/events",
            json={"events": [_valid_event()]},
        )
        assert resp.status_code in (401, 403)
