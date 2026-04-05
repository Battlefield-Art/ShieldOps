"""Tests for the Ingestion API (POST /api/v1/ingestion/events).

Covers:
  - Valid single event -> 202
  - Valid batch -> 202 with counts
  - Invalid payload -> 400
  - Duplicate event_id -> 409 (rejected in response)
  - Rate limit exceeded -> 429
  - Unknown fields accepted (schema evolution)
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.api.middleware.metrics import MetricsRegistry
from shieldops.api.routes import ingestion


def _create_test_app() -> FastAPI:
    """Create a minimal FastAPI app with the ingestion router."""
    app = FastAPI()
    app.include_router(ingestion.router, prefix="/api/v1")
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
def _reset_state() -> Any:
    """Reset module-level state between tests."""
    ingestion._redis = None
    MetricsRegistry.reset_instance()
    yield
    ingestion._redis = None
    MetricsRegistry.reset_instance()


@pytest.fixture
def client() -> TestClient:
    """TestClient with auth bypassed."""
    app = _create_test_app()

    async def _mock() -> UserResponse:
        return _mock_user()

    app.dependency_overrides[get_current_user] = _mock
    return TestClient(app, raise_server_exceptions=False)


def _valid_event(**overrides: Any) -> dict[str, Any]:
    """Generate a valid ingestion event payload."""
    base: dict[str, Any] = {
        "source_provider": "aws",
        "event_type": "api_activity",
        "timestamp": "2026-04-04T12:00:00Z",
        "raw_event": {"action": "AssumeRole", "principal": "arn:aws:iam::123:role/test"},
    }
    base.update(overrides)
    return base


# ================================================================
# Single event ingestion
# ================================================================


class TestSingleEventIngestion:
    """POST /api/v1/ingestion/events with a single JSON object."""

    def test_valid_single_event_returns_202(self, client: TestClient) -> None:
        resp = client.post("/api/v1/ingestion/events", json=_valid_event())
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 1
        assert data["rejected"] == 0
        assert len(data["events"]) == 1
        assert data["events"][0]["status"] == "accepted"

    def test_single_event_with_severity(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/ingestion/events",
            json=_valid_event(severity="high"),
        )
        assert resp.status_code == 202
        assert resp.json()["accepted"] == 1

    def test_single_event_auto_generates_event_id(self, client: TestClient) -> None:
        """event_id is auto-generated when not provided."""
        resp = client.post("/api/v1/ingestion/events", json=_valid_event())
        assert resp.status_code == 202
        event_id = resp.json()["events"][0]["event_id"]
        assert event_id  # non-empty UUID string

    def test_single_event_with_explicit_event_id(self, client: TestClient) -> None:
        eid = str(uuid4())
        resp = client.post(
            "/api/v1/ingestion/events",
            json=_valid_event(event_id=eid),
        )
        assert resp.status_code == 202
        assert resp.json()["events"][0]["event_id"] == eid


# ================================================================
# Batch ingestion
# ================================================================


class TestBatchIngestion:
    """POST /api/v1/ingestion/events with a JSON array."""

    def test_valid_batch_returns_202(self, client: TestClient) -> None:
        events = [
            _valid_event(source_provider="aws"),
            _valid_event(source_provider="crowdstrike"),
            _valid_event(source_provider="splunk"),
        ]
        resp = client.post("/api/v1/ingestion/events", json=events)
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 3
        assert data["rejected"] == 0
        assert len(data["events"]) == 3

    def test_empty_batch_returns_202(self, client: TestClient) -> None:
        resp = client.post("/api/v1/ingestion/events", json=[])
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 0
        assert data["rejected"] == 0
        assert data["events"] == []

    def test_partial_failure_in_batch(self, client: TestClient) -> None:
        """Valid + invalid events in same batch -> partial acceptance."""
        events = [
            _valid_event(),
            {"source_provider": "", "event_type": "bad"},  # missing required fields
            _valid_event(source_provider="splunk"),
        ]
        resp = client.post("/api/v1/ingestion/events", json=events)
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 2
        assert data["rejected"] == 1
        rejected = [e for e in data["events"] if e["status"] == "rejected"]
        assert len(rejected) == 1
        assert rejected[0]["message"] is not None


# ================================================================
# Validation errors -> 400 / rejection
# ================================================================


class TestValidationErrors:
    """Invalid payloads should be rejected."""

    def test_invalid_json_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/ingestion/events",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    def test_missing_source_provider_rejected(self, client: TestClient) -> None:
        event = _valid_event()
        del event["source_provider"]
        resp = client.post("/api/v1/ingestion/events", json=event)
        assert resp.status_code == 202
        data = resp.json()
        assert data["rejected"] == 1
        assert "source_provider" in data["events"][0]["message"]

    def test_missing_timestamp_rejected(self, client: TestClient) -> None:
        event = _valid_event()
        del event["timestamp"]
        resp = client.post("/api/v1/ingestion/events", json=event)
        assert resp.status_code == 202
        assert resp.json()["rejected"] == 1

    def test_missing_raw_event_rejected(self, client: TestClient) -> None:
        event = _valid_event()
        del event["raw_event"]
        resp = client.post("/api/v1/ingestion/events", json=event)
        assert resp.status_code == 202
        assert resp.json()["rejected"] == 1

    def test_non_object_payload_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/ingestion/events",
            content=b'"just a string"',
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400


# ================================================================
# Schema evolution — unknown fields accepted
# ================================================================


class TestSchemaEvolution:
    """Unknown fields in events should NOT cause rejection."""

    def test_extra_fields_in_event_accepted(self, client: TestClient) -> None:
        event = _valid_event(
            custom_field="hello",
            nested_extra={"foo": "bar"},
        )
        resp = client.post("/api/v1/ingestion/events", json=event)
        assert resp.status_code == 202
        assert resp.json()["accepted"] == 1

    def test_extra_fields_in_raw_event_accepted(self, client: TestClient) -> None:
        event = _valid_event(
            raw_event={"action": "test", "new_field_2027": True, "deep": {"nested": 1}},
        )
        resp = client.post("/api/v1/ingestion/events", json=event)
        assert resp.status_code == 202
        assert resp.json()["accepted"] == 1


# ================================================================
# Deduplication -> 409 (rejected with duplicate reason)
# ================================================================


class TestDeduplication:
    """Duplicate event_ids should be rejected when Redis is available."""

    def test_duplicate_event_id_rejected(self, client: TestClient) -> None:
        """Second submission of the same event_id is rejected."""
        mock_redis = AsyncMock()
        # First call: not a duplicate; second call: is a duplicate
        mock_redis.exists = AsyncMock(side_effect=[0, 1])
        mock_redis.set = AsyncMock()
        ingestion._redis = mock_redis

        eid = str(uuid4())
        event = _valid_event(event_id=eid)

        # First submission — accepted
        resp1 = client.post("/api/v1/ingestion/events", json=event)
        assert resp1.status_code == 202
        assert resp1.json()["accepted"] == 1

        # Second submission — rejected as duplicate
        resp2 = client.post("/api/v1/ingestion/events", json=event)
        assert resp2.status_code == 202
        data = resp2.json()
        assert data["rejected"] == 1
        assert data["events"][0]["status"] == "rejected"
        assert "duplicate" in data["events"][0]["message"]

    def test_dedup_skipped_when_redis_unavailable(self, client: TestClient) -> None:
        """When Redis is None, dedup is skipped (fail-open)."""
        ingestion._redis = None
        eid = str(uuid4())
        event = _valid_event(event_id=eid)

        resp1 = client.post("/api/v1/ingestion/events", json=event)
        resp2 = client.post("/api/v1/ingestion/events", json=event)

        assert resp1.status_code == 202
        assert resp1.json()["accepted"] == 1
        # Without Redis, duplicate is accepted (fail-open)
        assert resp2.status_code == 202
        assert resp2.json()["accepted"] == 1

    def test_dedup_fail_open_on_redis_error(self, client: TestClient) -> None:
        """Redis errors don't block ingestion."""
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(side_effect=ConnectionError("redis down"))
        ingestion._redis = mock_redis

        resp = client.post("/api/v1/ingestion/events", json=_valid_event())
        assert resp.status_code == 202
        assert resp.json()["accepted"] == 1


# ================================================================
# Rate limiting -> 429
# ================================================================


class TestRateLimiting:
    """Ingestion rate limiter returns 429 when tier limit is exceeded."""

    def test_rate_limit_exceeded_returns_429(self) -> None:
        """Middleware returns 429 with Retry-After when byte limit exceeded."""
        from shieldops.api.middleware.ingestion_rate_limiter import (
            IngestionRateLimiter,
        )

        app = _create_test_app()

        async def _mock() -> UserResponse:
            return _mock_user()

        app.dependency_overrides[get_current_user] = _mock

        # Mock Redis that reports we've used more than the starter limit
        mock_redis = AsyncMock()
        starter_limit = 5 * 1024**3
        # incrby returns current total — exceed limit
        mock_redis.incrby = AsyncMock(return_value=starter_limit + 1000)
        mock_redis.expire = AsyncMock()

        app.add_middleware(IngestionRateLimiter, redis=mock_redis)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/ingestion/events",
            json=_valid_event(),
        )
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_rate_limit_allows_under_limit(self) -> None:
        """Requests under the limit pass through normally."""
        from shieldops.api.middleware.ingestion_rate_limiter import (
            IngestionRateLimiter,
        )

        app = _create_test_app()

        async def _mock() -> UserResponse:
            return _mock_user()

        app.dependency_overrides[get_current_user] = _mock

        mock_redis = AsyncMock()
        mock_redis.incrby = AsyncMock(return_value=1024)  # 1 KB used
        mock_redis.expire = AsyncMock()

        app.add_middleware(IngestionRateLimiter, redis=mock_redis)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/ingestion/events",
            json=_valid_event(),
        )
        assert resp.status_code == 202


# ================================================================
# Prometheus metrics
# ================================================================


class TestMetrics:
    """Verify Prometheus-compatible metrics are recorded."""

    def test_accepted_event_increments_counter(self, client: TestClient) -> None:
        client.post("/api/v1/ingestion/events", json=_valid_event())
        registry = MetricsRegistry.get_instance()
        # Check that the events total counter was incremented
        matching = [k for k in registry.counters if "ingestion_events_total" in k]
        assert len(matching) > 0
        assert any(registry.counters[k] >= 1 for k in matching)

    def test_rejected_event_increments_rejected_counter(self, client: TestClient) -> None:
        bad_event = {"event_type": "bad"}  # missing required fields
        client.post("/api/v1/ingestion/events", json=bad_event)
        registry = MetricsRegistry.get_instance()
        matching = [k for k in registry.counters if "ingestion_rejected_total" in k]
        assert len(matching) > 0

    def test_bytes_counter_incremented(self, client: TestClient) -> None:
        client.post("/api/v1/ingestion/events", json=_valid_event())
        registry = MetricsRegistry.get_instance()
        matching = [k for k in registry.counters if "ingestion_bytes_total" in k]
        assert len(matching) > 0
        assert any(registry.counters[k] > 0 for k in matching)


# ================================================================
# Health endpoint
# ================================================================


class TestIngestionHealth:
    """GET /api/v1/ingestion/health."""

    def test_health_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/v1/ingestion/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
