"""Unit tests for bulk upload + agent telemetry ingestion endpoints.

Covers GitHub issue #204:

* CSV upload accepted, parsed, stored
* JSON upload accepted, parsed, stored
* Job status tracking (queued / processing / complete / failed)
* Agent telemetry events accepted through pipeline
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.routes import agent_telemetry, bulk_upload
from shieldops.api.routes.bulk_upload import _reset_jobs
from shieldops.storage.singleton import reset_event_store, set_event_store

# ---------------------------------------------------------------------------
# In-memory mock EventStore (mirrors DuckDBEventStore.insert_events interface)
# ---------------------------------------------------------------------------


class _MockEventStore:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def insert_events(self, records: list[dict[str, Any]]) -> None:
        self.records.extend(records)

    def clear(self) -> None:
        self.records.clear()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store() -> Any:
    s = _MockEventStore()
    set_event_store(s)
    yield s
    reset_event_store()


@pytest.fixture()
def client(store: _MockEventStore) -> TestClient:
    app = FastAPI()
    app.include_router(bulk_upload.router, prefix="/api/v1")
    app.include_router(agent_telemetry.router, prefix="/api/v1")
    _reset_jobs()
    return TestClient(app)


# ---------------------------------------------------------------------------
# CSV upload
# ---------------------------------------------------------------------------


class TestCSVUpload:
    def test_csv_upload_accepted_parsed_stored(
        self, client: TestClient, store: _MockEventStore
    ) -> None:
        csv_body = (
            "event_name,user,source_ip,severity\n"
            "login,alice,10.0.0.1,low\n"
            "logout,bob,10.0.0.2,low\n"
            "failed_login,eve,203.0.113.5,high\n"
        )
        resp = client.post(
            "/api/v1/ingest/upload",
            files={"file": ("events.csv", csv_body, "text/csv")},
            data={"source_provider": "bulk_upload", "org_id": "org-1"},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()

        assert body["file_format"] == "csv"
        assert body["background"] is False
        assert body["status"] == "complete"
        job_id = body["job_id"]

        # Three rows -> three stored records.
        assert len(store.records) == 3
        assert all(r["source_provider"] == "bulk_upload" for r in store.records)
        assert all(r["org_id"] == "org-1" for r in store.records)

        status = client.get(f"/api/v1/ingest/upload/{job_id}").json()
        assert status["status"] == "complete"
        assert status["accepted"] == 3
        assert status["rejected"] == 0

    def test_csv_empty_file_rejected(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/ingest/upload",
            files={"file": ("empty.csv", "", "text/csv")},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# JSON upload
# ---------------------------------------------------------------------------


class TestJSONUpload:
    def test_json_list_upload_accepted_parsed_stored(
        self, client: TestClient, store: _MockEventStore
    ) -> None:
        payload = [
            {"event_name": "login", "user": "alice"},
            {"event_name": "logout", "user": "bob"},
        ]
        resp = client.post(
            "/api/v1/ingest/upload",
            files={
                "file": (
                    "events.json",
                    json.dumps(payload),
                    "application/json",
                ),
            },
            data={"source_provider": "bulk_upload"},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["file_format"] == "json"
        assert body["status"] == "complete"
        assert len(store.records) == 2

    def test_json_wrapped_records_accepted(
        self, client: TestClient, store: _MockEventStore
    ) -> None:
        payload = {"records": [{"a": 1}, {"b": 2}, {"c": 3}]}
        resp = client.post(
            "/api/v1/ingest/upload",
            files={
                "file": (
                    "wrapped.json",
                    json.dumps(payload),
                    "application/json",
                ),
            },
        )
        assert resp.status_code == 202
        assert len(store.records) == 3

    def test_ndjson_upload(self, client: TestClient, store: _MockEventStore) -> None:
        ndjson = '{"a": 1}\n{"a": 2}\n{"a": 3}\n'
        resp = client.post(
            "/api/v1/ingest/upload",
            files={"file": ("events.ndjson", ndjson, "application/json")},
        )
        assert resp.status_code == 202
        assert len(store.records) == 3


# ---------------------------------------------------------------------------
# Job status tracking
# ---------------------------------------------------------------------------


class TestJobStatus:
    def test_job_status_after_complete(self, client: TestClient, store: _MockEventStore) -> None:
        csv_body = "x,y\n1,2\n3,4\n"
        resp = client.post(
            "/api/v1/ingest/upload",
            files={"file": ("small.csv", csv_body, "text/csv")},
        )
        job_id = resp.json()["job_id"]

        status_resp = client.get(f"/api/v1/ingest/upload/{job_id}")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["job_id"] == job_id
        assert data["status"] == "complete"
        assert data["file_format"] == "csv"
        assert data["accepted"] == 2
        assert data["rejected"] == 0
        assert data["created_at"] <= data["updated_at"]

    def test_job_status_unknown_returns_404(self, client: TestClient) -> None:
        resp = client.get("/api/v1/ingest/upload/does-not-exist")
        assert resp.status_code == 404

    def test_background_task_for_large_files(
        self, client: TestClient, store: _MockEventStore, monkeypatch: Any
    ) -> None:
        # Force background path by lowering the threshold.
        monkeypatch.setattr(bulk_upload, "_BACKGROUND_THRESHOLD_BYTES", 10)

        csv_body = "a,b\n" + "\n".join(f"{i},{i + 1}" for i in range(100)) + "\n"
        resp = client.post(
            "/api/v1/ingest/upload",
            files={"file": ("big.csv", csv_body, "text/csv")},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["background"] is True
        job_id = body["job_id"]

        # TestClient runs BackgroundTasks synchronously after the response is
        # sent, so by the time we poll the job should be complete.
        status = client.get(f"/api/v1/ingest/upload/{job_id}").json()
        assert status["status"] == "complete"
        assert status["accepted"] == 100


# ---------------------------------------------------------------------------
# Agent telemetry endpoint
# ---------------------------------------------------------------------------


class TestAgentTelemetry:
    def test_single_tool_call_event_accepted(
        self, client: TestClient, store: _MockEventStore
    ) -> None:
        event = {
            "event_type": "tool_call",
            "agent_id": "agent-abc",
            "agent_name": "investigation",
            "framework": "langchain",
            "tool_name": "search_web",
            "decision": "allow",
            "severity": "info",
            "inputs": {"query": "hello"},
            "outputs": {"ok": True},
        }
        resp = client.post(
            "/api/v1/ingest/telemetry",
            json=event,
            headers={"X-Org-Id": "org-9"},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["events_accepted"] == 1
        assert body["events_rejected"] == 0
        assert body["source"] == "shieldops_sdk"
        assert len(store.records) == 1
        assert store.records[0]["source_provider"] == "shieldops_sdk"
        assert store.records[0]["org_id"] == "org-9"

    def test_batch_telemetry_events_accepted(
        self, client: TestClient, store: _MockEventStore
    ) -> None:
        payload = {
            "events": [
                {
                    "event_type": "tool_call",
                    "tool_name": "search",
                    "decision": "allow",
                },
                {
                    "event_type": "decision",
                    "tool_name": "exec_shell",
                    "decision": "block",
                    "severity": "high",
                },
                {
                    "event_type": "metric",
                    "metrics": {"latency_ms": 123},
                },
            ],
        }
        resp = client.post("/api/v1/ingest/telemetry", json=payload)
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["events_accepted"] == 3
        assert body["events_rejected"] == 0
        assert len(store.records) == 3
        assert all(r["source_provider"] == "shieldops_sdk" for r in store.records)

    def test_empty_telemetry_batch_rejected(self, client: TestClient) -> None:
        resp = client.post("/api/v1/ingest/telemetry", json={"events": []})
        assert resp.status_code == 400
