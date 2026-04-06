"""Event Pattern Discovery Engine Discovers recurring event sequences and temporal patterns to..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventPatternDiscoveryEngine = engine(
    "EventPatternDiscoveryEngine",
    description="Event Pattern Discovery Engine Discovers recurring event sequences and temp...",
    enums={
        "frequency": EnumDef(
            "PatternFrequency",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "IRREGULAR": "irregular",
            },
        ),
        "confidence": EnumDef(
            "PatternConfidence",
            {
                "CONFIRMED": "confirmed",
                "PROBABLE": "probable",
                "SUSPECTED": "suspected",
                "UNVERIFIED": "unverified",
            },
        ),
        "event_category": EnumDef(
            "EventCategory",
            {
                "DEPLOYMENT": "deployment",
                "ALERT": "alert",
                "SCALING": "scaling",
                "FAILURE": "failure",
                "CONFIG_CHANGE": "config_change",
                "TRAFFIC_SHIFT": "traffic_shift",
            },
        ),
    },
    record_fields=[
        FieldDef("event_sequence", str, ""),
        FieldDef("first_seen_at", float, 0.0),
        FieldDef("occurrence_count", int, 0),
        FieldDef("services_involved", int, 0),
        FieldDef("lead_time_minutes", float, 0.0),
    ],
    key_field="pattern_id",
)

# Backward-compatible re-exports
PatternFrequency = EventPatternDiscoveryEngine.PatternFrequency
PatternConfidence = EventPatternDiscoveryEngine.PatternConfidence
EventCategory = EventPatternDiscoveryEngine.EventCategory
EventPatternRecord = EventPatternDiscoveryEngine.Record
EventPatternAnalysis = EventPatternDiscoveryEngine.Analysis
EventPatternReport = EventPatternDiscoveryEngine.Report
