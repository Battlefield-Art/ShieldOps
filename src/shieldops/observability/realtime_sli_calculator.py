"""RealtimeSliCalculator — real-time SLI engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RealtimeSliCalculator = engine(
    "RealtimeSliCalculator",
    description="Realtime SLI Calculator. Calculates service level indicators in real-time a...",
    enums={
        "sli_type": EnumDef(
            "SliType",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
            },
        ),
        "window": EnumDef(
            "CalculationWindow",
            {
                "MINUTES_1": "minutes_1",
                "MINUTES_5": "minutes_5",
                "MINUTES_15": "minutes_15",
                "HOUR_1": "hour_1",
            },
        ),
        "health": EnumDef(
            "SliHealth",
            {
                "HEALTHY": "healthy",
                "WARNING": "warning",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("target", float, 99.9),
    ],
)

# Backward-compatible re-exports
SliType = RealtimeSliCalculator.SliType
CalculationWindow = RealtimeSliCalculator.CalculationWindow
SliHealth = RealtimeSliCalculator.SliHealth
SliRecord = RealtimeSliCalculator.Record
SliAnalysis = RealtimeSliCalculator.Analysis
SliReport = RealtimeSliCalculator.Report
