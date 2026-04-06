"""SecurityAutomationAuditTrail — maintain audit trails for all security automation actions."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityAutomationAuditTrail = engine(
    "SecurityAutomationAuditTrail",
    description="Maintain audit trails for all security automation actions.",
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
SecurityType = SecurityAutomationAuditTrail.SecurityType
SecuritySource = SecurityAutomationAuditTrail.SecuritySource
SecurityLevel = SecurityAutomationAuditTrail.SecurityLevel
SecurityRecord = SecurityAutomationAuditTrail.Record
SecurityAnalysis = SecurityAutomationAuditTrail.Analysis
SecurityReport = SecurityAutomationAuditTrail.Report
