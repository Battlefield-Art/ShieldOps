"""Availability Pattern Engine compute temporal availability patterns, detect recurring unavai..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AvailabilityPatternEngine = engine(
    "AvailabilityPatternEngine",
    description="Compute temporal availability patterns, detect recurring unavailability, ra...",
    enums={
        "time_window": EnumDef(
            "TimeWindow",
            {
                "PEAK_HOURS": "peak_hours",
                "OFF_HOURS": "off_hours",
                "WEEKEND": "weekend",
                "MAINTENANCE": "maintenance",
            },
        ),
        "availability_trend": EnumDef(
            "AvailabilityTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
            },
        ),
        "pattern_type": EnumDef(
            "PatternType",
            {
                "PERIODIC": "periodic",
                "SPORADIC": "sporadic",
                "CORRELATED": "correlated",
                "RANDOM": "random",
            },
        ),
    },
    record_fields=[
        FieldDef("availability_pct", float, 99.9),
        FieldDef("outage_minutes", float, 0.0),
        FieldDef("occurrences", int, 0),
        FieldDef("region", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
TimeWindow = AvailabilityPatternEngine.TimeWindow
AvailabilityTrend = AvailabilityPatternEngine.AvailabilityTrend
PatternType = AvailabilityPatternEngine.PatternType
AvailabilityPatternRecord = AvailabilityPatternEngine.Record
AvailabilityPatternAnalysis = AvailabilityPatternEngine.Analysis
AvailabilityPatternReport = AvailabilityPatternEngine.Report
