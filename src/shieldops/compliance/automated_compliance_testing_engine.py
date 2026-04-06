"""AutomatedComplianceTestingEngine — automate compliance testing and evidence collection."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomatedComplianceTestingEngine = engine(
    "AutomatedComplianceTestingEngine",
    description="Automate compliance testing and evidence collection.",
    enums={
        "record_type": EnumDef(
            "AutomatedType",
            {
                "CONTROL": "control",
                "POLICY": "policy",
                "REGULATION": "regulation",
                "STANDARD": "standard",
                "FRAMEWORK": "framework",
            },
        ),
        "source": EnumDef(
            "AutomatedSource",
            {
                "AUDIT": "audit",
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "CONTINUOUS_MONITOR": "continuous_monitor",
                "THIRD_PARTY": "third_party",
            },
        ),
        "level": EnumDef(
            "AutomatedLevel",
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
AutomatedType = AutomatedComplianceTestingEngine.AutomatedType
AutomatedSource = AutomatedComplianceTestingEngine.AutomatedSource
AutomatedLevel = AutomatedComplianceTestingEngine.AutomatedLevel
AutomatedRecord = AutomatedComplianceTestingEngine.Record
AutomatedAnalysis = AutomatedComplianceTestingEngine.Analysis
AutomatedReport = AutomatedComplianceTestingEngine.Report
