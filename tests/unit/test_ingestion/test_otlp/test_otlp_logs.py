"""Tests for OTLP log ingestion (HTTP JSON, HTTP Protobuf, gRPC)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.ingestion.otlp.parser import (
    _coerce_any_value,
    _coerce_attributes,
    otlp_http_json_to_events,
    otlp_log_record_to_event,
)
from shieldops.ingestion.pipeline import BatchResult

# ---------------------------------------------------------------------------
# Sample OTLP/HTTP JSON payload — shape matches ExportLogsServiceRequest
# ---------------------------------------------------------------------------

SAMPLE_OTLP_JSON: dict[str, Any] = {
    "resourceLogs": [
        {
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "shieldops-api"}},
                    {"key": "host.name", "value": {"stringValue": "pod-1"}},
                    {"key": "service.instance.id", "value": {"intValue": "42"}},
                ]
            },
            "scopeLogs": [
                {
                    "scope": {"name": "shieldops.logger", "version": "1.2.3"},
                    "logRecords": [
                        {
                            "timeUnixNano": "1700000000000000000",
                            "severityNumber": 17,
                            "severityText": "ERROR",
                            "body": {"stringValue": "Authentication failed"},
                            "attributes": [
                                {"key": "user.id", "value": {"stringValue": "u-1"}},
                                {"key": "http.status_code", "value": {"intValue": "401"}},
                            ],
                            "traceId": "abcd1234",
                            "spanId": "ff00",
                        },
                        {
                            "timeUnixNano": "1700000000500000000",
                            "severityNumber": 9,
                            "body": {"stringValue": "User login"},
                        },
                    ],
                }
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------


class TestParserHelpers:
    def test_coerce_any_value_primitives(self) -> None:
        assert _coerce_any_value({"stringValue": "hi"}) == "hi"
        assert _coerce_any_value({"intValue": "42"}) == 42
        assert _coerce_any_value({"boolValue": True}) is True
        assert _coerce_any_value({"doubleValue": 1.5}) == 1.5

    def test_coerce_any_value_array(self) -> None:
        val = {
            "arrayValue": {
                "values": [
                    {"stringValue": "a"},
                    {"intValue": "1"},
                ]
            }
        }
        assert _coerce_any_value(val) == ["a", 1]

    def test_coerce_any_value_kvlist(self) -> None:
        val = {
            "kvlistValue": {
                "values": [
                    {"key": "k1", "value": {"stringValue": "v1"}},
                    {"key": "k2", "value": {"intValue": "2"}},
                ]
            }
        }
        assert _coerce_any_value(val) == {"k1": "v1", "k2": 2}

    def test_coerce_attributes(self) -> None:
        attrs = [
            {"key": "a", "value": {"stringValue": "x"}},
            {"key": "b", "value": {"intValue": "7"}},
        ]
        assert _coerce_attributes(attrs) == {"a": "x", "b": 7}


# ---------------------------------------------------------------------------
# JSON → events conversion
# ---------------------------------------------------------------------------


class TestOtlpJsonToEvents:
    def test_parses_sample_payload(self) -> None:
        events = otlp_http_json_to_events(SAMPLE_OTLP_JSON)
        assert len(events) == 2

    def test_preserves_resource_attributes(self) -> None:
        events = otlp_http_json_to_events(SAMPLE_OTLP_JSON)
        evt = events[0]
        assert evt["resource_attributes"]["service.name"] == "shieldops-api"
        assert evt["resource_attributes"]["host.name"] == "pod-1"
        assert evt["resource_attributes"]["service.instance.id"] == 42

    def test_preserves_log_attributes_and_body(self) -> None:
        events = otlp_http_json_to_events(SAMPLE_OTLP_JSON)
        evt = events[0]
        assert evt["body"] == "Authentication failed"
        assert evt["severity_number"] == 17
        assert evt["severity_text"] == "ERROR"
        assert evt["attributes"]["user.id"] == "u-1"
        assert evt["attributes"]["http.status_code"] == 401
        assert evt["scope_name"] == "shieldops.logger"
        assert evt["scope_version"] == "1.2.3"
        assert evt["_transport"] == "otlp"

    def test_defaults_severity_text_when_missing(self) -> None:
        events = otlp_http_json_to_events(SAMPLE_OTLP_JSON)
        info_evt = events[1]
        assert info_evt["severity_number"] == 9
        assert info_evt["severity_text"] == "INFO"

    def test_empty_payload_returns_empty(self) -> None:
        assert otlp_http_json_to_events({}) == []
        assert otlp_http_json_to_events({"resourceLogs": []}) == []

    def test_log_record_to_event_timestamp_iso(self) -> None:
        evt = otlp_log_record_to_event(
            {"timeUnixNano": "1700000000000000000", "body": {"stringValue": "x"}}
        )
        assert evt["timestamp"].startswith("2023-11-14T")


# ---------------------------------------------------------------------------
# HTTP endpoint — JSON
# ---------------------------------------------------------------------------


def _make_http_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    from shieldops.api.routes import otlp_logs as otlp_module

    calls: list[tuple[list[dict[str, Any]], str, str]] = []

    async def fake_process_batch(
        events: list[dict[str, Any]], source_provider: str, org_id: str
    ) -> BatchResult:
        calls.append((list(events), source_provider, org_id))
        return BatchResult(
            accepted=len(events),
            rejected=0,
            event_ids=[f"evt-{i}" for i in range(len(events))],
        )

    monkeypatch.setattr(otlp_module, "process_batch", fake_process_batch)

    app = FastAPI()
    app.include_router(otlp_module.router)
    app.state.test_calls = calls  # type: ignore[attr-defined]
    return app


class TestOtlpHttpEndpointJson:
    def test_accepts_otlp_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_http_app(monkeypatch)
        client = TestClient(app)
        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/json", "X-Org-Id": "acme"},
            json=SAMPLE_OTLP_JSON,
        )
        assert response.status_code == 202
        body = response.json()
        assert body["events_accepted"] == 2
        assert body["events_rejected"] == 0
        assert body["source"] == "otel"

        calls = app.state.test_calls  # type: ignore[attr-defined]
        assert len(calls) == 1
        events, source, org = calls[0]
        assert source == "otel"
        assert org == "acme"
        assert events[0]["body"] == "Authentication failed"
        assert events[0]["resource_attributes"]["service.name"] == "shieldops-api"

    def test_rejects_empty_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_http_app(monkeypatch)
        client = TestClient(app)
        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/json"},
            content=b"",
        )
        assert response.status_code == 400

    def test_rejects_invalid_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_http_app(monkeypatch)
        client = TestClient(app)
        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/json"},
            content=b"{not json",
        )
        assert response.status_code == 400

    def test_rejects_empty_logs_data(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_http_app(monkeypatch)
        client = TestClient(app)
        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/json"},
            json={"resourceLogs": []},
        )
        assert response.status_code == 400

    def test_defaults_org_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_http_app(monkeypatch)
        client = TestClient(app)
        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/json"},
            json=SAMPLE_OTLP_JSON,
        )
        assert response.status_code == 202
        calls = app.state.test_calls  # type: ignore[attr-defined]
        assert calls[0][2] == "default"


# ---------------------------------------------------------------------------
# HTTP endpoint — Protobuf (mocked parser)
# ---------------------------------------------------------------------------


class TestOtlpHttpEndpointProtobuf:
    def test_accepts_protobuf_via_mocked_parser(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from shieldops.api.routes import otlp_logs as otlp_module

        # Monkeypatch both the protobuf parser (to avoid needing the real
        # opentelemetry-proto runtime) and process_batch.
        def fake_proto_parser(payload: bytes) -> list[dict[str, Any]]:
            assert payload == b"\x01\x02\x03"
            return [
                {
                    "timestamp": "2024-01-01T00:00:00+00:00",
                    "severity_number": 9,
                    "severity_text": "INFO",
                    "body": "hello",
                    "attributes": {},
                    "resource_attributes": {"service.name": "svc"},
                    "scope_name": "",
                    "scope_version": "",
                    "trace_id": "",
                    "span_id": "",
                    "_transport": "otlp",
                }
            ]

        async def fake_process_batch(
            events: list[dict[str, Any]], source_provider: str, org_id: str
        ) -> BatchResult:
            return BatchResult(
                accepted=len(events),
                rejected=0,
                event_ids=["evt-0"],
            )

        monkeypatch.setattr(otlp_module, "otlp_http_protobuf_to_events", fake_proto_parser)
        monkeypatch.setattr(otlp_module, "process_batch", fake_process_batch)

        app = FastAPI()
        app.include_router(otlp_module.router)
        client = TestClient(app)

        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/x-protobuf"},
            content=b"\x01\x02\x03",
        )
        assert response.status_code == 202
        body = response.json()
        assert body["events_accepted"] == 1
        assert body["content_type"] == "application/x-protobuf"

    def test_protobuf_runtime_error_returns_415(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from shieldops.api.routes import otlp_logs as otlp_module

        def broken(payload: bytes) -> list[dict[str, Any]]:
            raise RuntimeError("opentelemetry-proto is not installed")

        monkeypatch.setattr(otlp_module, "otlp_http_protobuf_to_events", broken)

        app = FastAPI()
        app.include_router(otlp_module.router)
        client = TestClient(app)
        response = client.post(
            "/ingest/otlp/logs",
            headers={"Content-Type": "application/x-protobuf"},
            content=b"\x01",
        )
        assert response.status_code == 415


# ---------------------------------------------------------------------------
# gRPC server lifecycle (skipped when grpc is not installed)
# ---------------------------------------------------------------------------


class TestGrpcServer:
    @pytest.mark.asyncio
    async def test_start_and_stop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        try:
            import grpc  # noqa: F401
            from opentelemetry.proto.collector.logs.v1 import (  # noqa: F401
                logs_service_pb2,
                logs_service_pb2_grpc,
            )
        except Exception:
            pytest.skip("grpc or opentelemetry-proto not installed")

        from shieldops.ingestion.otlp import grpc_server as gs

        captured: list[tuple[list[dict[str, Any]], str, str]] = []

        async def fake_process_batch(
            events: list[dict[str, Any]], source_provider: str, org_id: str
        ) -> BatchResult:
            captured.append((list(events), source_provider, org_id))
            return BatchResult(accepted=len(events), rejected=0, event_ids=["evt-0"])

        monkeypatch.setattr(gs, "process_batch", fake_process_batch)

        # Start on an ephemeral port — let the OS pick.
        server = await gs.start_otlp_grpc_server(host="127.0.0.1", port=0, org_id="acme")
        assert server is not None
        assert gs.get_otlp_grpc_server() is server

        await gs.stop_otlp_grpc_server(grace=0.1)
        assert gs.get_otlp_grpc_server() is None

    @pytest.mark.asyncio
    async def test_servicer_exports_events(self, monkeypatch: pytest.MonkeyPatch) -> None:
        try:
            from opentelemetry.proto.collector.logs.v1 import (
                logs_service_pb2,
                logs_service_pb2_grpc,
            )
            from opentelemetry.proto.common.v1 import common_pb2
            from opentelemetry.proto.resource.v1 import resource_pb2
        except Exception:
            pytest.skip("opentelemetry-proto not installed")

        from shieldops.ingestion.otlp import grpc_server as gs

        captured: list[tuple[list[dict[str, Any]], str, str]] = []

        async def fake_process_batch(
            events: list[dict[str, Any]], source_provider: str, org_id: str
        ) -> BatchResult:
            captured.append((list(events), source_provider, org_id))
            return BatchResult(accepted=len(events), rejected=0, event_ids=["evt-0"])

        monkeypatch.setattr(gs, "process_batch", fake_process_batch)

        servicer = gs._build_logs_service(logs_service_pb2, logs_service_pb2_grpc, org_id="acme")

        # Build a real ExportLogsServiceRequest with one log record.
        req = logs_service_pb2.ExportLogsServiceRequest()
        rl = req.resource_logs.add()
        rl.resource.CopyFrom(
            resource_pb2.Resource(
                attributes=[
                    common_pb2.KeyValue(
                        key="service.name",
                        value=common_pb2.AnyValue(string_value="shieldops"),
                    )
                ]
            )
        )
        sl = rl.scope_logs.add()
        sl.scope.CopyFrom(common_pb2.InstrumentationScope(name="test", version="1"))
        lr = sl.log_records.add()
        lr.time_unix_nano = 1_700_000_000_000_000_000
        lr.severity_number = 17
        lr.severity_text = "ERROR"
        lr.body.CopyFrom(common_pb2.AnyValue(string_value="boom"))
        lr.attributes.append(
            common_pb2.KeyValue(key="user.id", value=common_pb2.AnyValue(string_value="u-1"))
        )

        resp = await servicer.Export(req, context=None)
        assert isinstance(resp, logs_service_pb2.ExportLogsServiceResponse)

        assert len(captured) == 1
        events, source, org = captured[0]
        assert source == "otel"
        assert org == "acme"
        assert len(events) == 1
        evt = events[0]
        assert evt["body"] == "boom"
        assert evt["severity_number"] == 17
        assert evt["severity_text"] == "ERROR"
        assert evt["attributes"]["user.id"] == "u-1"
        assert evt["resource_attributes"]["service.name"] == "shieldops"
        assert evt["scope_name"] == "test"
