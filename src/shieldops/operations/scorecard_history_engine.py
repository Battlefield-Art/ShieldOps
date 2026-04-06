"""ScorecardHistoryEngine -- track scorecard history."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ScorecardHistoryEngine = engine(
    "ScorecardHistoryEngine",
    module="operations",  # uses record_item
    description="Track scorecard history and trends.",
    enums={
        "period": EnumDef(
            "ScorePeriod",
            {
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
            },
        ),
        "component": EnumDef(
            "ScoreComponent",
            {
                "DETECTION": "detection",
                "PREVENTION": "prevention",
                "RESPONSE": "response",
                "COMPLIANCE": "compliance",
                "RISK": "risk",
            },
        ),
        "delta": EnumDef(
            "DeltaDirection",
            {
                "UP": "up",
                "DOWN": "down",
                "FLAT": "flat",
            },
        ),
    },
    record_fields=[
        FieldDef("previous_score", float, 0.0),
    ],
)

# Backward-compatible re-exports
ScorePeriod = ScorecardHistoryEngine.ScorePeriod
ScoreComponent = ScorecardHistoryEngine.ScoreComponent
DeltaDirection = ScorecardHistoryEngine.DeltaDirection
ScorecardHistoryRecord = ScorecardHistoryEngine.Record
ScorecardHistoryAnalysis = ScorecardHistoryEngine.Analysis
ScorecardHistoryReport = ScorecardHistoryEngine.Report
