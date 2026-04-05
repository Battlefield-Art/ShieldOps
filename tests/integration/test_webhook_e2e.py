"""End-to-end integration tests: webhook -> OCSF normalize -> DuckDB -> query.

Uses a real (temporary) DuckDB database and the full OCSF mapper pipeline.
Auth is bypassed via dependency override so that we can test the data path
in isolation.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("duckdb", reason="duckdb required for e2e webhook tests")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.routes import event_query, webhooks
from shieldops.storage.duckdb_backend import DuckDBEventStore
from shieldops.storage.singleton import reset_event_store, set_event_store

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TEST_ORG = "test-org-001"


def _make_app(store: DuckDBEventStore) -> FastAPI:
    """Build a minimal FastAPI app with webhook + query routes wired to *store*."""
    app = FastAPI()

    # Wire store into the event_query module
    event_query.set_store(store)

    # Register routes
    app.include_router(webhooks.router, prefix="/api/v1")
    app.include_router(event_query.router, prefix="/api/v1")

    return app


@pytest.fixture()
def _env(tmp_path: Any) -> Any:
    """Set up a temp DuckDB store and FastAPI TestClient."""
    db_file = str(tmp_path / "test_events.duckdb")
    store = DuckDBEventStore(db_path=db_file, parquet_path=str(tmp_path / "parquet"))
    set_event_store(store)

    app = _make_app(store)

    # Override auth dependency to bypass JWT for testing
    from shieldops.api.auth.dependencies import get_current_user
    from shieldops.api.auth.models import UserResponse

    fake_user = UserResponse(
        id=_TEST_ORG,
        email="test@shieldops.dev",
        name="Test User",
        role="admin",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: fake_user

    client = TestClient(app)
    yield client, store

    # Teardown
    reset_event_store()


# ---------------------------------------------------------------------------
# Helper — query events by source_provider
# ---------------------------------------------------------------------------


def _query_events(client: TestClient, source_provider: str) -> list[dict[str, Any]]:
    """Query DuckDB via the event-query endpoint for a given source_provider."""
    resp = client.post(
        "/api/v1/event-query/",
        json={
            "sql": f"SELECT * FROM events WHERE source_provider = '{source_provider}'",  # noqa: S608  # nosec B608
            "limit": 100,
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data.get("items", [])


# ---------------------------------------------------------------------------
# CloudTrail e2e
# ---------------------------------------------------------------------------


class TestCloudTrailWebhook:
    """CloudTrail webhook -> OCSF -> DuckDB -> query."""

    def test_single_api_event(self, _env: Any) -> None:
        client, store = _env

        cloudtrail_event = {
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2026-04-05T10:00:00Z",
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/admin",
                "userName": "admin",
            },
            "sourceIPAddress": "198.51.100.1",
            "requestParameters": {"instancesSet": {"items": []}},
        }

        resp = client.post(
            "/api/v1/ingest/webhook/cloudtrail",
            json=cloudtrail_event,
            headers={"X-Org-Id": _TEST_ORG},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["source"] == "cloudtrail"
        assert body["events_accepted"] == 1
        assert len(body["event_ids"]) == 1

        # Verify in DuckDB
        items = _query_events(client, "cloudtrail")
        assert len(items) >= 1
        item = items[0]
        assert item["source_provider"] == "cloudtrail"
        assert item["event_type"] == "api_activity"

    def test_sns_notification_with_records(self, _env: Any) -> None:
        client, store = _env

        payload = {
            "Records": [
                {
                    "eventName": "ConsoleLogin",
                    "eventSource": "signin.amazonaws.com",
                    "eventTime": "2026-04-05T09:00:00Z",
                    "userIdentity": {"userName": "alice"},
                    "sourceIPAddress": "203.0.113.5",
                    "responseElements": {"ConsoleLogin": "Success"},
                },
                {
                    "eventName": "RunInstances",
                    "eventSource": "ec2.amazonaws.com",
                    "eventTime": "2026-04-05T09:01:00Z",
                    "userIdentity": {"arn": "arn:aws:iam::123:user/bob"},
                },
            ]
        }

        resp = client.post(
            "/api/v1/ingest/webhook/cloudtrail",
            json=payload,
            headers={"X-Org-Id": _TEST_ORG},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["events_accepted"] == 2

        items = _query_events(client, "cloudtrail")
        assert len(items) == 2
        event_types = {i["event_type"] for i in items}
        assert "authentication" in event_types
        assert "api_activity" in event_types

    def test_empty_payload_returns_400(self, _env: Any) -> None:
        client, _ = _env
        resp = client.post(
            "/api/v1/ingest/webhook/cloudtrail",
            json={"unrelated": "data"},
            headers={"X-Org-Id": _TEST_ORG},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# CrowdStrike e2e
# ---------------------------------------------------------------------------


class TestCrowdStrikeWebhook:
    """CrowdStrike webhook -> OCSF -> DuckDB -> query."""

    def test_single_detection(self, _env: Any) -> None:
        client, store = _env

        detection = {
            "detection_id": "ldt:abcdef123456",
            "detect_name": "Malicious PowerShell Execution",
            "severity": 4,
            "confidence": 85,
            "first_behavior": "2026-04-05T08:00:00Z",
            "last_behavior": "2026-04-05T08:05:00Z",
            "device": {
                "device_id": "dev-001",
                "hostname": "workstation-42",
                "os_version": "Windows 11",
                "platform_name": "Windows",
            },
            "behaviors": [
                {"tactic": "Execution", "technique": "T1059.001"},
            ],
        }

        resp = client.post(
            "/api/v1/ingest/webhook/crowdstrike",
            json=detection,
            headers={"X-Org-Id": _TEST_ORG},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["source"] == "crowdstrike"
        assert body["events_accepted"] == 1

        items = _query_events(client, "crowdstrike")
        assert len(items) >= 1
        item = items[0]
        assert item["source_provider"] == "crowdstrike"
        assert item["event_type"] == "security_finding"

    def test_fdr_batch(self, _env: Any) -> None:
        client, store = _env

        payload = {
            "resources": [
                {
                    "detection_id": "ldt:det1",
                    "detect_name": "Detection 1",
                    "severity": 3,
                    "confidence": 70,
                },
                {
                    "detection_id": "ldt:det2",
                    "detect_name": "Detection 2",
                    "severity": 5,
                    "confidence": 95,
                },
            ]
        }

        resp = client.post(
            "/api/v1/ingest/webhook/crowdstrike",
            json=payload,
            headers={"X-Org-Id": _TEST_ORG},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["events_accepted"] == 2

        items = _query_events(client, "crowdstrike")
        assert len(items) == 2

    def test_empty_payload_returns_400(self, _env: Any) -> None:
        client, _ = _env
        resp = client.post(
            "/api/v1/ingest/webhook/crowdstrike",
            json={"unrelated": "data"},
            headers={"X-Org-Id": _TEST_ORG},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GuardDuty e2e
# ---------------------------------------------------------------------------


class TestGuardDutyWebhook:
    """GuardDuty webhook -> OCSF -> DuckDB -> query."""

    def test_direct_finding(self, _env: Any) -> None:
        client, store = _env

        finding = {
            "Id": "gd-finding-001",
            "Title": "Unauthorized API Call from Known Malicious IP",
            "Description": "An API call was made from a known malicious IP.",
            "Severity": 8.5,
            "Confidence": 90,
            "Type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "CreatedAt": "2026-04-05T07:00:00Z",
            "UpdatedAt": "2026-04-05T07:30:00Z",
            "Resource": {
                "ResourceType": "AccessKey",
                "InstanceDetails": {
                    "InstanceId": "i-0abcd1234efgh5678",
                },
            },
            "Service": {
                "EventFirstSeen": "2026-04-05T07:00:00Z",
                "EventLastSeen": "2026-04-05T07:30:00Z",
            },
        }

        resp = client.post(
            "/api/v1/ingest/webhook/guardduty",
            json=finding,
            headers={"X-Org-Id": _TEST_ORG},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["source"] == "guardduty"
        assert body["events_accepted"] == 1

        items = _query_events(client, "guardduty")
        assert len(items) >= 1
        item = items[0]
        assert item["source_provider"] == "guardduty"
        assert item["event_type"] == "security_finding"

    def test_eventbridge_format(self, _env: Any) -> None:
        client, store = _env

        eventbridge_event = {
            "version": "0",
            "id": "eb-001",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "detail": {
                "Id": "gd-finding-002",
                "Title": "EC2 Instance communicating with known C2 server",
                "Severity": 9.0,
                "Confidence": 95,
                "Type": "Trojan:EC2/C&CActivity.B",
                "Resource": {
                    "ResourceType": "Instance",
                    "InstanceDetails": {"InstanceId": "i-9999"},
                },
            },
        }

        resp = client.post(
            "/api/v1/ingest/webhook/guardduty",
            json=eventbridge_event,
            headers={"X-Org-Id": _TEST_ORG},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["events_accepted"] == 1

        items = _query_events(client, "guardduty")
        assert len(items) >= 1

    def test_empty_payload_returns_400(self, _env: Any) -> None:
        client, _ = _env
        resp = client.post(
            "/api/v1/ingest/webhook/guardduty",
            json={"unrelated": "data"},
            headers={"X-Org-Id": _TEST_ORG},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Cross-source test
# ---------------------------------------------------------------------------


class TestCrossSourceQuery:
    """Verify events from all three sources are queryable together."""

    def test_all_three_sources_stored(self, _env: Any) -> None:
        client, store = _env

        # Ingest one from each source
        client.post(
            "/api/v1/ingest/webhook/cloudtrail",
            json={
                "eventName": "CreateBucket",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2026-04-05T12:00:00Z",
                "userIdentity": {"userName": "ops"},
            },
            headers={"X-Org-Id": _TEST_ORG},
        )

        client.post(
            "/api/v1/ingest/webhook/crowdstrike",
            json={
                "detection_id": "ldt:cross-test",
                "detect_name": "Cross Test Detection",
                "severity": 2,
                "confidence": 50,
            },
            headers={"X-Org-Id": _TEST_ORG},
        )

        client.post(
            "/api/v1/ingest/webhook/guardduty",
            json={
                "Id": "gd-cross-test",
                "Title": "Cross Test Finding",
                "Severity": 3.0,
                "Confidence": 60,
                "Type": "Recon:EC2/PortProbeUnprotectedPort",
            },
            headers={"X-Org-Id": _TEST_ORG},
        )

        # Query all events (no source_provider filter)
        resp = client.post(
            "/api/v1/event-query/",
            json={"sql": "SELECT * FROM events", "limit": 100},
        )
        assert resp.status_code == 200
        data = resp.json()
        items = data["items"]
        providers = {i["source_provider"] for i in items}
        assert "cloudtrail" in providers
        assert "crowdstrike" in providers
        assert "guardduty" in providers
