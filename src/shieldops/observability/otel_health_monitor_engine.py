"""OtelHealthMonitorEngine — monitor OTel Collector health via zpages and internal metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelHealthMonitorEngine = engine(
    "OtelHealthMonitorEngine",
    description="Monitor OTel Collector health via zpages and internal metrics.",
    enums={
        "health_indicator": EnumDef(
            "HealthIndicator",
            {
                "CPU_USAGE": "cpu_usage",
                "MEMORY_USAGE": "memory_usage",
                "QUEUE_DEPTH": "queue_depth",
                "DROPPED_DATA": "dropped_data",
            },
        ),
        "collector_status": EnumDef(
            "CollectorStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "UNHEALTHY": "unhealthy",
                "UNREACHABLE": "unreachable",
            },
        ),
        "alert_severity": EnumDef(
            "AlertSeverity",
            {
                "INFO": "info",
                "WARNING": "warning",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("collector_id", str, ""),
    ],
)

# Backward-compatible re-exports
HealthIndicator = OtelHealthMonitorEngine.HealthIndicator
CollectorStatus = OtelHealthMonitorEngine.CollectorStatus
AlertSeverity = OtelHealthMonitorEngine.AlertSeverity
OtelHealthMonitorRecord = OtelHealthMonitorEngine.Record
OtelHealthMonitorAnalysis = OtelHealthMonitorEngine.Analysis
OtelHealthMonitorReport = OtelHealthMonitorEngine.Report
