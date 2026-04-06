"""Event Sourcing Pattern Engine — analyze event store growth, detect projection lag, rank agg..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventSourcingPatternEngine = engine(
    "EventSourcingPatternEngine",
    description="Analyze event store growth, detect projection lag, rank aggregates by compl...",
    enums={
        "event_type": EnumDef(
            "EventType",
            {
                "DOMAIN": "domain",
                "INTEGRATION": "integration",
                "SYSTEM": "system",
                "SNAPSHOT": "snapshot",
            },
        ),
        "projection_status": EnumDef(
            "ProjectionStatus",
            {
                "CURRENT": "current",
                "LAGGING": "lagging",
                "STALE": "stale",
                "REBUILDING": "rebuilding",
            },
        ),
        "store_growth": EnumDef(
            "StoreGrowth",
            {
                "RAPID": "rapid",
                "STEADY": "steady",
                "SLOW": "slow",
                "STABLE": "stable",
            },
        ),
    },
    record_fields=[
        FieldDef("event_count", int, 0),
        FieldDef("projection_lag_ms", float, 0.0),
        FieldDef("store_size_mb", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="aggregate_id",
)

# Backward-compatible re-exports
EventType = EventSourcingPatternEngine.EventType
ProjectionStatus = EventSourcingPatternEngine.ProjectionStatus
StoreGrowth = EventSourcingPatternEngine.StoreGrowth
EventSourcingRecord = EventSourcingPatternEngine.Record
EventSourcingAnalysis = EventSourcingPatternEngine.Analysis
EventSourcingReport = EventSourcingPatternEngine.Report
