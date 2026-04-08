"""Tests for the GET /investigations/{id}/timeline endpoint.

After RFC #245 PR-4 (#273) the route is wired to
``InvestigationTimelineService`` via ``Depends(get_service(...))``
rather than the deleted ``Repository`` god object. These tests
override the cached dependency to inject an ``AsyncMock`` service
so we can exercise route behaviour without a real DB.

Coverage: mixed events, empty timeline, ordering, 404, event_type
filter, auth, DB unavailable, and the service-id pass-through.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.routes import investigations
from shieldops.db.services import get_service
from shieldops.db.services.investigation_timeline import InvestigationTimelineService


def _create_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(investigations.router, prefix="/api/v1")
    return app


def _make_timeline_events() -> list[dict[str, Any]]:
    return [
        {
            "id": "inv-inv-abc123",
            "timestamp": "2026-02-19T10:00:00+00:00",
            "type": "investigation",
            "action": "investigation_completed",
            "actor": "agent:investigation",
            "severity": "warning",
            "details": {
                "alert_id": "alert-001",
                "alert_name": "HighCPU",
                "confidence": 0.92,
                "duration_ms": 4500,
                "error": None,
            },
        },
        {
            "id": "rem-rem-001",
            "timestamp": "2026-02-19T10:01:00+00:00",
            "type": "remediation",
            "action": "restart_service_completed",
            "actor": "agent:remediation",
            "severity": "medium",
            "details": {
                "remediation_id": "rem-001",
                "action_type": "restart_service",
                "target_resource": "web-api",
                "environment": "production",
                "validation_passed": True,
                "duration_ms": 2000,
                "error": None,
            },
        },
        {
            "id": "aud-aud-001",
            "timestamp": "2026-02-19T10:02:00+00:00",
            "type": "audit",
            "action": "restart_service",
            "actor": "agent:remediation-01",
            "severity": "medium",
            "details": {
                "audit_id": "aud-001",
                "agent_type": "remediation",
                "target_resource": "web-api",
                "environment": "production",
                "policy_evaluation": "allowed",
                "approval_status": None,
                "outcome": "success",
                "reasoning": "inv-abc123: service restart",
            },
        },
    ]


@pytest.fixture
def mock_service() -> AsyncMock:
    """An AsyncMock that quacks like ``InvestigationTimelineService``."""
    svc = AsyncMock(spec=InvestigationTimelineService)
    svc.build_timeline = AsyncMock(return_value=_make_timeline_events())
    svc.filter_by_type = AsyncMock(
        side_effect=lambda inv_id, et: [e for e in _make_timeline_events() if e["type"] == et]
    )
    return svc


def _wire_app(
    mock_service: AsyncMock | None,
    *,
    with_user: bool = True,
) -> TestClient:
    """Build a TestClient with the timeline service + (optionally) auth wired."""
    app = _create_test_app()

    if mock_service is not None:
        # Override the cached dep so the route resolves to our mock.
        dep = get_service(InvestigationTimelineService)
        app.dependency_overrides[dep] = lambda: mock_service

    if with_user:
        from shieldops.api.auth.dependencies import get_current_user
        from shieldops.api.auth.models import UserResponse, UserRole

        user = UserResponse(
            id="viewer-1",
            email="viewer@test.com",
            name="Viewer",
            role=UserRole.VIEWER,
            is_active=True,
        )

        async def _mock_user() -> UserResponse:
            return user

        app.dependency_overrides[get_current_user] = _mock_user

    return TestClient(app, raise_server_exceptions=False)


# ================================================================
# Mixed event types
# ================================================================


class TestTimelineMixedEvents:
    def test_returns_mixed_event_types(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["investigation_id"] == "inv-abc123"
        assert data["total"] == 3
        assert {e["type"] for e in data["events"]} == {
            "investigation",
            "remediation",
            "audit",
        }

    def test_event_shape(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline")
        event = resp.json()["events"][0]
        for key in ("id", "timestamp", "type", "action", "actor", "details"):
            assert key in event


# ================================================================
# Empty timeline → 404 (the new contract)
# ================================================================


class TestTimelineEmpty:
    def test_empty_timeline_returns_404(self, mock_service: AsyncMock) -> None:
        mock_service.build_timeline.return_value = []
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline")
        assert resp.status_code == 404


# ================================================================
# Chronological ordering
# ================================================================


class TestTimelineOrdering:
    def test_events_chronologically_ordered(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline")
        timestamps = [e["timestamp"] for e in resp.json()["events"]]
        assert timestamps == sorted(timestamps)


# ================================================================
# Investigation not found (404)
# ================================================================


class TestTimelineNotFound:
    def test_returns_404_for_unknown_investigation(self, mock_service: AsyncMock) -> None:
        mock_service.build_timeline.return_value = []
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/nonexistent/timeline")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()


# ================================================================
# Event type filtering
# ================================================================


class TestTimelineEventTypeFilter:
    def test_filter_by_remediation_type(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline?event_type=remediation")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert all(e["type"] == "remediation" for e in data["events"])

    def test_filter_by_nonexistent_type_returns_404(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline?event_type=security")
        # No events match → 404 under the new "empty == not found" contract
        assert resp.status_code == 404


# ================================================================
# Authentication required
# ================================================================


class TestTimelineAuth:
    def test_unauthenticated_request_rejected(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service, with_user=False)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline")
        assert resp.status_code in (401, 403)
        # Service should not be called
        mock_service.build_timeline.assert_not_called()
        mock_service.filter_by_type.assert_not_called()


# ================================================================
# DB unavailable (503)
# ================================================================


class TestTimelineDbUnavailable:
    def test_returns_503_when_session_factory_missing(self) -> None:
        # Don't override the timeline service dep — let it fall through to
        # the real ``get_service`` factory, which raises 503 because the
        # bare TestClient app has no session_factory on app.state.
        client = _wire_app(mock_service=None, with_user=True)
        resp = client.get("/api/v1/investigations/inv-abc123/timeline")
        assert resp.status_code == 503


# ================================================================
# Service called with correct investigation_id
# ================================================================


class TestTimelineServiceCall:
    def test_passes_correct_id_to_service(self, mock_service: AsyncMock) -> None:
        client = _wire_app(mock_service)
        client.get("/api/v1/investigations/inv-xyz/timeline")
        mock_service.build_timeline.assert_called_once_with("inv-xyz")
