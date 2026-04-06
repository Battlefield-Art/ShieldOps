"""Telemetry Pipeline Health Monitor Engine — monitor telemetry pipeline health, detect pipeli..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TelemetryPipelineHealthMonitorEngine = engine(
    "TelemetryPipelineHealthMonitorEngine",
    description="Monitor telemetry pipeline health, detect pipeline bottlenecks, forecast pi...",
    enums={
        "pipeline_stage": EnumDef(
            "PipelineStage",
            {
                "COLLECTION": "collection",
                "PROCESSING": "processing",
                "EXPORT": "export",
                "STORAGE": "storage",
            },
        ),
        "health_status": EnumDef(
            "HealthStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "UNHEALTHY": "unhealthy",
                "UNKNOWN": "unknown",
            },
        ),
        "issue_type": EnumDef(
            "IssueType",
            {
                "DATA_LOSS": "data_loss",
                "LATENCY": "latency",
                "BACKPRESSURE": "backpressure",
                "CONFIGURATION": "configuration",
            },
        ),
    },
    record_fields=[
        FieldDef("stage_name", str, ""),
        FieldDef("throughput_eps", float, 0.0),
        FieldDef("drop_rate", float, 0.0),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("queue_depth", int, 0),
        FieldDef("capacity_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="pipeline_id",
)

# Backward-compatible re-exports
PipelineStage = TelemetryPipelineHealthMonitorEngine.PipelineStage
HealthStatus = TelemetryPipelineHealthMonitorEngine.HealthStatus
IssueType = TelemetryPipelineHealthMonitorEngine.IssueType
TelemetryPipelineRecord = TelemetryPipelineHealthMonitorEngine.Record
TelemetryPipelineAnalysis = TelemetryPipelineHealthMonitorEngine.Analysis
TelemetryPipelineReport = TelemetryPipelineHealthMonitorEngine.Report
