"""SecurityControlAutomationScorer — score automation coverage of security controls."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityControlAutomationScorer = engine(
    "SecurityControlAutomationScorer",
    description="Score automation coverage of security controls.",
    enums={
        "record_type": EnumDef(
            "SecurityControlType",
            {
                "CONTROL": "control",
                "POLICY": "policy",
                "REGULATION": "regulation",
                "STANDARD": "standard",
                "FRAMEWORK": "framework",
            },
        ),
        "source": EnumDef(
            "SecurityControlSource",
            {
                "AUDIT": "audit",
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "CONTINUOUS_MONITOR": "continuous_monitor",
                "THIRD_PARTY": "third_party",
            },
        ),
        "level": EnumDef(
            "SecurityControlLevel",
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
SecurityControlType = SecurityControlAutomationScorer.SecurityControlType
SecurityControlSource = SecurityControlAutomationScorer.SecurityControlSource
SecurityControlLevel = SecurityControlAutomationScorer.SecurityControlLevel
SecurityControlRecord = SecurityControlAutomationScorer.Record
SecurityControlAnalysis = SecurityControlAutomationScorer.Analysis
SecurityControlReport = SecurityControlAutomationScorer.Report
