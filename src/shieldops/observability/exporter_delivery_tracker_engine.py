"""Exporter Delivery Tracker Engine — compute delivery reliability, detect export backpressure..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExporterDeliveryTrackerEngine = engine(
    "ExporterDeliveryTrackerEngine",
    description="Compute delivery reliability, detect export backpressure, rank backends by...",
    enums={
        "exporter_backend": EnumDef(
            "ExporterBackend",
            {
                "SPLUNK": "splunk",
                "DATADOG": "datadog",
                "PROMETHEUS_REMOTE": "prometheus_remote",
                "JAEGER": "jaeger",
            },
        ),
        "delivery_status": EnumDef(
            "DeliveryStatus",
            {
                "DELIVERED": "delivered",
                "RETRYING": "retrying",
                "DROPPED": "dropped",
                "QUEUED": "queued",
            },
        ),
        "failure_reason": EnumDef(
            "ExportFailureReason",
            {
                "BACKEND_UNAVAILABLE": "backend_unavailable",
                "AUTH_EXPIRED": "auth_expired",
                "RATE_LIMITED": "rate_limited",
                "PAYLOAD_TOO_LARGE": "payload_too_large",
            },
        ),
    },
    record_fields=[
        FieldDef("items_sent", int, 0),
        FieldDef("items_dropped", int, 0),
        FieldDef("queue_size", int, 0),
        FieldDef("cost_per_million_items", float, 0.0),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="exporter_id",
)

# Backward-compatible re-exports
ExporterBackend = ExporterDeliveryTrackerEngine.ExporterBackend
DeliveryStatus = ExporterDeliveryTrackerEngine.DeliveryStatus
ExportFailureReason = ExporterDeliveryTrackerEngine.ExportFailureReason
ExporterDeliveryRecord = ExporterDeliveryTrackerEngine.Record
ExporterDeliveryAnalysis = ExporterDeliveryTrackerEngine.Analysis
ExporterDeliveryReport = ExporterDeliveryTrackerEngine.Report
