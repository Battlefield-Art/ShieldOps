"""OtelExporterReliabilityEngine — Track OTel exporter reliability and retry behavior."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelExporterReliabilityEngine = engine(
    "OtelExporterReliabilityEngine",
    description="Track OTel exporter reliability and retry behavior engine.",
    enums={
        "exporter_health": EnumDef(
            "ExporterHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "FAILING": "failing",
                "DEAD": "dead",
            },
        ),
        "retry_outcome": EnumDef(
            "RetryOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "EXHAUSTED": "exhausted",
            },
        ),
        "backend_type": EnumDef(
            "BackendType",
            {
                "OTLP_GRPC": "otlp_grpc",
                "OTLP_HTTP": "otlp_http",
                "KAFKA": "kafka",
                "PROMETHEUS_REMOTE_WRITE": "prometheus_remote_write",
            },
        ),
    },
    record_fields=[
        FieldDef("total_sent", int, 0),
        FieldDef("total_failed", int, 0),
        FieldDef("retry_count", int, 0),
        FieldDef("latency_ms", float, 0.0),
    ],
)

# Backward-compatible re-exports
ExporterHealth = OtelExporterReliabilityEngine.ExporterHealth
RetryOutcome = OtelExporterReliabilityEngine.RetryOutcome
BackendType = OtelExporterReliabilityEngine.BackendType
OtelExporterReliabilityRecord = OtelExporterReliabilityEngine.Record
OtelExporterReliabilityAnalysis = OtelExporterReliabilityEngine.Analysis
OtelExporterReliabilityReport = OtelExporterReliabilityEngine.Report
