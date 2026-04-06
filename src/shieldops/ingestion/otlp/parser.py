"""OTLP log record parsing.

Converts OpenTelemetry ``LogRecord`` payloads (from OTLP/HTTP JSON, OTLP/HTTP
Protobuf, or OTLP/gRPC) into plain raw-event dicts that the ShieldOps ingestion
pipeline can normalize and store.

OTLP schema reference
---------------------
A ``LogsData`` message contains repeated ``ResourceLogs``. Each ``ResourceLogs``
has a ``resource`` (with attributes) and repeated ``ScopeLogs``. Each
``ScopeLogs`` has an ``InstrumentationScope`` and repeated ``LogRecord``.

A ``LogRecord`` carries:

* ``time_unix_nano`` / ``observed_time_unix_nano``
* ``severity_number`` (0-24) and ``severity_text``
* ``body`` (AnyValue)
* ``attributes`` (repeated KeyValue)
* ``trace_id`` / ``span_id`` (bytes)

Both JSON and Protobuf wire formats describe the same structure — we accept
either and emit a normalized dict per log record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Severity mapping — OTEL severity_number → rough text
# ---------------------------------------------------------------------------

_OTEL_SEVERITY_TEXT: dict[int, str] = {
    0: "UNSPECIFIED",
    1: "TRACE",
    2: "TRACE2",
    3: "TRACE3",
    4: "TRACE4",
    5: "DEBUG",
    6: "DEBUG2",
    7: "DEBUG3",
    8: "DEBUG4",
    9: "INFO",
    10: "INFO2",
    11: "INFO3",
    12: "INFO4",
    13: "WARN",
    14: "WARN2",
    15: "WARN3",
    16: "WARN4",
    17: "ERROR",
    18: "ERROR2",
    19: "ERROR3",
    20: "ERROR4",
    21: "FATAL",
    22: "FATAL2",
    23: "FATAL3",
    24: "FATAL4",
}


# ---------------------------------------------------------------------------
# AnyValue / KeyValue coercion — works for both JSON-dict and protobuf
# ---------------------------------------------------------------------------


def _coerce_any_value(value: Any) -> Any:  # noqa: PLR0911
    """Turn an OTLP ``AnyValue`` (dict or protobuf) into a plain Python value."""
    if value is None:
        return None

    # Protobuf AnyValue — has WhichOneof("value")
    which = getattr(value, "WhichOneof", None)
    if callable(which):
        try:
            field = which("value")
        except Exception:
            field = None
        if field is None:
            return None
        raw = getattr(value, field, None)
        if field == "string_value":
            return raw
        if field in ("int_value", "double_value", "bool_value"):
            return raw
        if field == "bytes_value":
            try:
                return raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
            except Exception:
                return None
        if field == "array_value":
            values = getattr(raw, "values", []) or []
            return [_coerce_any_value(v) for v in values]
        if field == "kvlist_value":
            kvs = getattr(raw, "values", []) or []
            return {kv.key: _coerce_any_value(kv.value) for kv in kvs}
        return None

    # JSON dict AnyValue — {"stringValue": "..."} etc.
    if isinstance(value, dict):
        if "stringValue" in value:
            return value["stringValue"]
        if "intValue" in value:
            try:
                return int(value["intValue"])
            except (TypeError, ValueError):
                return value["intValue"]
        if "doubleValue" in value:
            return value["doubleValue"]
        if "boolValue" in value:
            return bool(value["boolValue"])
        if "bytesValue" in value:
            return value["bytesValue"]
        if "arrayValue" in value:
            arr = value["arrayValue"] or {}
            return [_coerce_any_value(v) for v in arr.get("values", [])]
        if "kvlistValue" in value:
            kvl = value["kvlistValue"] or {}
            return {
                kv.get("key", ""): _coerce_any_value(kv.get("value"))
                for kv in kvl.get("values", [])
            }
        # Already a plain dict — return as-is
        return value

    # Primitive
    return value


def _coerce_attributes(attrs: Any) -> dict[str, Any]:
    """Turn a repeated KeyValue sequence into a flat dict."""
    if attrs is None:
        return {}

    result: dict[str, Any] = {}

    # Protobuf repeated KeyValue
    try:
        iterator = iter(attrs)
    except TypeError:
        return {}

    for kv in iterator:
        if isinstance(kv, dict):
            key = kv.get("key", "")
            value = kv.get("value")
        else:
            key = getattr(kv, "key", "")
            value = getattr(kv, "value", None)
        if not key:
            continue
        result[str(key)] = _coerce_any_value(value)
    return result


def _nanos_to_iso(time_unix_nano: Any) -> str:
    """Convert a Unix nanosecond timestamp to an ISO-8601 string."""
    if time_unix_nano in (None, 0, "0", ""):
        return datetime.now(tz=UTC).isoformat()
    try:
        nanos = int(time_unix_nano)
    except (TypeError, ValueError):
        return datetime.now(tz=UTC).isoformat()
    return datetime.fromtimestamp(nanos / 1_000_000_000, tz=UTC).isoformat()


def _bytes_to_hex(value: Any) -> str:
    """Convert a bytes (protobuf) or string (JSON hex) trace/span id to hex."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return str(value)


# ---------------------------------------------------------------------------
# Single LogRecord → raw event dict
# ---------------------------------------------------------------------------


def otlp_log_record_to_event(
    log_record: Any,
    resource_attributes: dict[str, Any] | None = None,
    scope_name: str = "",
    scope_version: str = "",
) -> dict[str, Any]:
    """Convert a single OTLP LogRecord (dict or protobuf) to a raw event dict."""
    is_dict = isinstance(log_record, dict)

    if is_dict:
        time_unix_nano = log_record.get("timeUnixNano") or log_record.get("observedTimeUnixNano")
        severity_number = int(log_record.get("severityNumber", 0) or 0)
        severity_text = log_record.get("severityText") or _OTEL_SEVERITY_TEXT.get(
            severity_number, "UNSPECIFIED"
        )
        body = _coerce_any_value(log_record.get("body"))
        attributes = _coerce_attributes(log_record.get("attributes", []))
        trace_id = log_record.get("traceId", "")
        span_id = log_record.get("spanId", "")
    else:
        time_unix_nano = getattr(log_record, "time_unix_nano", 0) or getattr(
            log_record, "observed_time_unix_nano", 0
        )
        severity_number = int(getattr(log_record, "severity_number", 0) or 0)
        severity_text = getattr(log_record, "severity_text", "") or _OTEL_SEVERITY_TEXT.get(
            severity_number, "UNSPECIFIED"
        )
        body = _coerce_any_value(getattr(log_record, "body", None))
        attributes = _coerce_attributes(getattr(log_record, "attributes", []))
        trace_id = _bytes_to_hex(getattr(log_record, "trace_id", b""))
        span_id = _bytes_to_hex(getattr(log_record, "span_id", b""))

    return {
        "timestamp": _nanos_to_iso(time_unix_nano),
        "severity_number": severity_number,
        "severity_text": severity_text,
        "body": body,
        "attributes": attributes,
        "resource_attributes": dict(resource_attributes or {}),
        "scope_name": scope_name,
        "scope_version": scope_version,
        "trace_id": trace_id,
        "span_id": span_id,
        "_transport": "otlp",
    }


# ---------------------------------------------------------------------------
# LogsData traversal — shared between JSON and Protobuf
# ---------------------------------------------------------------------------


def _iter_resource_logs_dict(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk a JSON OTLP LogsData payload and return raw event dicts."""
    events: list[dict[str, Any]] = []
    resource_logs = body.get("resourceLogs") or body.get("resource_logs") or []
    for rl in resource_logs:
        if not isinstance(rl, dict):
            continue
        resource = rl.get("resource") or {}
        resource_attrs = _coerce_attributes(resource.get("attributes", []))
        scope_logs = rl.get("scopeLogs") or rl.get("scope_logs") or []
        for sl in scope_logs:
            if not isinstance(sl, dict):
                continue
            scope = sl.get("scope") or {}
            scope_name = str(scope.get("name", "") or "")
            scope_version = str(scope.get("version", "") or "")
            log_records = sl.get("logRecords") or sl.get("log_records") or []
            for lr in log_records:
                if not isinstance(lr, dict):
                    continue
                events.append(
                    otlp_log_record_to_event(lr, resource_attrs, scope_name, scope_version)
                )
    return events


def _iter_resource_logs_proto(logs_data: Any) -> list[dict[str, Any]]:
    """Walk a protobuf OTLP LogsData message and return raw event dicts."""
    events: list[dict[str, Any]] = []
    for rl in getattr(logs_data, "resource_logs", []) or []:
        resource = getattr(rl, "resource", None)
        resource_attrs = _coerce_attributes(getattr(resource, "attributes", [])) if resource else {}
        for sl in getattr(rl, "scope_logs", []) or []:
            scope = getattr(sl, "scope", None)
            scope_name = getattr(scope, "name", "") if scope else ""
            scope_version = getattr(scope, "version", "") if scope else ""
            for lr in getattr(sl, "log_records", []) or []:
                events.append(
                    otlp_log_record_to_event(
                        lr, resource_attrs, str(scope_name), str(scope_version)
                    )
                )
    return events


def otlp_http_json_to_events(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert an OTLP/HTTP JSON ``LogsData`` payload into raw event dicts."""
    if not isinstance(body, dict):
        return []
    # Both the collector export request and plain LogsData carry resourceLogs.
    return _iter_resource_logs_dict(body)


def otlp_http_protobuf_to_events(payload: bytes) -> list[dict[str, Any]]:
    """Convert an OTLP/HTTP Protobuf request body into raw event dicts.

    Raises ``RuntimeError`` if the opentelemetry-proto package is unavailable.
    """
    try:
        from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    except Exception as exc:  # pragma: no cover - import-time guard
        logger.warning("otlp.proto_unavailable", error=str(exc))
        raise RuntimeError("opentelemetry-proto is not installed") from exc

    request = logs_service_pb2.ExportLogsServiceRequest()
    request.ParseFromString(payload)
    return _iter_resource_logs_proto(request)
