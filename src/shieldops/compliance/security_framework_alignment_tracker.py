"""SecurityFrameworkAlignmentTracker — track alignment with security frameworks like nist and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityFrameworkAlignmentTracker = engine(
    "SecurityFrameworkAlignmentTracker",
    description="Track alignment with security frameworks like NIST and CIS.",
    enums={
        "record_type": EnumDef(
            "SecurityType",
            {
                "CONTROL": "control",
                "POLICY": "policy",
                "REGULATION": "regulation",
                "STANDARD": "standard",
                "FRAMEWORK": "framework",
            },
        ),
        "source": EnumDef(
            "SecuritySource",
            {
                "AUDIT": "audit",
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "CONTINUOUS_MONITOR": "continuous_monitor",
                "THIRD_PARTY": "third_party",
            },
        ),
        "level": EnumDef(
            "SecurityLevel",
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
SecurityType = SecurityFrameworkAlignmentTracker.SecurityType
SecuritySource = SecurityFrameworkAlignmentTracker.SecuritySource
SecurityLevel = SecurityFrameworkAlignmentTracker.SecurityLevel
SecurityRecord = SecurityFrameworkAlignmentTracker.Record
SecurityAnalysis = SecurityFrameworkAlignmentTracker.Analysis
SecurityReport = SecurityFrameworkAlignmentTracker.Report
