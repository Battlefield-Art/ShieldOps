"""CoverageGapTracker -- track coverage gaps."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CoverageGapTracker = engine(
    "CoverageGapTracker",
    module="operations",  # uses record_item
    description="Track and manage coverage gaps.",
    enums={
        "category": EnumDef(
            "GapCategory",
            {
                "DETECTION": "detection",
                "PREVENTION": "prevention",
                "RESPONSE": "response",
                "VISIBILITY": "visibility",
                "COMPLIANCE": "compliance",
            },
        ),
        "priority": EnumDef(
            "PriorityLevel",
            {
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "CRITICAL": "critical",
            },
        ),
        "closure": EnumDef(
            "ClosureRate",
            {
                "ON_TRACK": "on_track",
                "AT_RISK": "at_risk",
                "OVERDUE": "overdue",
                "CLOSED": "closed",
            },
        ),
    },
    record_fields=[
        FieldDef("owner", str, ""),
        FieldDef("target_date", str, ""),
    ],
)

# Backward-compatible re-exports
GapCategory = CoverageGapTracker.GapCategory
PriorityLevel = CoverageGapTracker.PriorityLevel
ClosureRate = CoverageGapTracker.ClosureRate
CoverageGapRecord = CoverageGapTracker.Record
CoverageGapAnalysis = CoverageGapTracker.Analysis
CoverageGapReport = CoverageGapTracker.Report
