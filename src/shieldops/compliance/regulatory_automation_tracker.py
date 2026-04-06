"""RegulatoryAutomationTracker — track regulatory compliance automation coverage."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RegulatoryAutomationTracker = engine(
    "RegulatoryAutomationTracker",
    description="Track regulatory compliance automation coverage.",
    enums={
        "record_type": EnumDef(
            "RegulatoryType",
            {
                "CONTROL": "control",
                "POLICY": "policy",
                "REGULATION": "regulation",
                "STANDARD": "standard",
                "FRAMEWORK": "framework",
            },
        ),
        "source": EnumDef(
            "RegulatorySource",
            {
                "AUDIT": "audit",
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "CONTINUOUS_MONITOR": "continuous_monitor",
                "THIRD_PARTY": "third_party",
            },
        ),
        "level": EnumDef(
            "RegulatoryLevel",
            {
                "COMPLIANT": "compliant",
                "PARTIAL": "partial",
                "NON_COMPLIANT": "non_compliant",
                "NOT_ASSESSED": "not_assessed",
                "EXEMPT": "exempt",
            },
        ),
    },
)

# Backward-compatible re-exports
RegulatoryType = RegulatoryAutomationTracker.RegulatoryType
RegulatorySource = RegulatoryAutomationTracker.RegulatorySource
RegulatoryLevel = RegulatoryAutomationTracker.RegulatoryLevel
RegulatoryRecord = RegulatoryAutomationTracker.Record
RegulatoryAnalysis = RegulatoryAutomationTracker.Analysis
RegulatoryReport = RegulatoryAutomationTracker.Report
