"""Bottleneck Tracker Engine — track resource bottleneck detection and resolution."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BottleneckTrackerEngine = engine(
    "BottleneckTrackerEngine",
    description="Track resource bottleneck detection and resolution across services.",
    enums={
        "bottleneck_type": EnumDef(
            "BottleneckType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "DISK_IO": "disk_io",
                "NETWORK": "network",
                "CONNECTION_POOL": "connection_pool",
            },
        ),
        "resolution_status": EnumDef(
            "ResolutionStatus",
            {
                "DETECTED": "detected",
                "INVESTIGATING": "investigating",
                "MITIGATED": "mitigated",
                "RESOLVED": "resolved",
                "RECURRING": "recurring",
            },
        ),
        "impact_level": EnumDef(
            "ImpactLevel",
            {
                "SERVICE_DOWN": "service_down",
                "DEGRADED": "degraded",
                "SLOW": "slow",
                "MINOR": "minor",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("affected_requests", int, 0),
        FieldDef("resolution_time_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
BottleneckType = BottleneckTrackerEngine.BottleneckType
ResolutionStatus = BottleneckTrackerEngine.ResolutionStatus
ImpactLevel = BottleneckTrackerEngine.ImpactLevel
BottleneckTrackerRecord = BottleneckTrackerEngine.Record
BottleneckTrackerAnalysis = BottleneckTrackerEngine.Analysis
BottleneckTrackerReport = BottleneckTrackerEngine.Report
