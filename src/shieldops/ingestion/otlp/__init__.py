"""OTLP (OpenTelemetry Protocol) log ingestion.

Provides OTLP/gRPC server + OTLP/HTTP parsing for log records and routes
them through the standard ingestion pipeline (OCSF normalize + event store).

OpenTelemetry packages are imported lazily so the rest of ShieldOps keeps
working in environments that only ship a subset of extras.
"""

from __future__ import annotations

from shieldops.ingestion.otlp.parser import (
    otlp_http_json_to_events,
    otlp_http_protobuf_to_events,
    otlp_log_record_to_event,
)

__all__ = [
    "otlp_http_json_to_events",
    "otlp_http_protobuf_to_events",
    "otlp_log_record_to_event",
]
