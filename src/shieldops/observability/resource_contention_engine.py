"""ResourceContentionEngine — Track and analyze resource contention events."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceContentionEngine = engine(
    "ResourceContentionEngine",
    description="Track and analyze resource contention events across infrastructure.",
    enums={
        "contention_type": EnumDef(
            "ContentionType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "DISK_IO": "disk_io",
                "NETWORK": "network",
                "LOCK": "lock",
            },
        ),
        "contention_severity": EnumDef(
            "ContentionSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NONE": "none",
            },
        ),
        "resolution_action": EnumDef(
            "ResolutionAction",
            {
                "SCALE_UP": "scale_up",
                "OPTIMIZE_QUERY": "optimize_query",
                "ADD_CACHE": "add_cache",
                "REDUCE_CONCURRENCY": "reduce_concurrency",
                "UPGRADE": "upgrade",
            },
        ),
    },
    record_fields=[
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("affected_pods", int, 0),
    ],
)

# Backward-compatible re-exports
ContentionType = ResourceContentionEngine.ContentionType
ContentionSeverity = ResourceContentionEngine.ContentionSeverity
ResolutionAction = ResourceContentionEngine.ResolutionAction
ResourceContentionRecord = ResourceContentionEngine.Record
ResourceContentionAnalysis = ResourceContentionEngine.Analysis
ResourceContentionReport = ResourceContentionEngine.Report
