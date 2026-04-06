"""OTelPipelineHealthEngine — monitor OTel collector pipeline health."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OTelPipelineHealthEngine = engine(
    "OTelPipelineHealthEngine",
    description="Monitor OTel collector pipeline health — dropped telemetry, queue depths, e...",
    enums={
        "signal_type": EnumDef(
            "PipelineSignalType",
            {
                "TRACES": "traces",
                "METRICS": "metrics",
                "LOGS": "logs",
                "PROFILES": "profiles",
            },
        ),
        "health_indicator": EnumDef(
            "HealthIndicator",
            {
                "THROUGHPUT": "throughput",
                "LATENCY": "latency",
                "DROP_RATE": "drop_rate",
                "QUEUE_DEPTH": "queue_depth",
            },
        ),
        "pipeline_status": EnumDef(
            "PipelineStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "BACKPRESSURE": "backpressure",
                "FAILING": "failing",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("threshold", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="collector_id",
)

# Backward-compatible re-exports
PipelineSignalType = OTelPipelineHealthEngine.PipelineSignalType
HealthIndicator = OTelPipelineHealthEngine.HealthIndicator
PipelineStatus = OTelPipelineHealthEngine.PipelineStatus
PipelineHealthRecord = OTelPipelineHealthEngine.Record
PipelineHealthAnalysis = OTelPipelineHealthEngine.Analysis
PipelineHealthReport = OTelPipelineHealthEngine.Report
