"""Compliance Aware Change Automator compliance-aware change automation with policy enforcement."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ComplianceAwareChangeAutomator = engine(
    "ComplianceAwareChangeAutomator",
    description="Compliance Aware Change Automator compliance-aware change automation with p...",
    enums={
        "change_category": EnumDef(
            "ChangeCategory",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "SECURITY": "security",
                "NETWORK": "network",
                "DATABASE": "database",
            },
        ),
        "compliance_check": EnumDef(
            "ComplianceCheck",
            {
                "SOC2_CONTROL": "soc2_control",
                "HIPAA_RULE": "hipaa_rule",
                "PCI_REQUIREMENT": "pci_requirement",
                "INTERNAL_POLICY": "internal_policy",
                "REGULATORY": "regulatory",
            },
        ),
        "compliance_result": EnumDef(
            "ComplianceResult",
            {
                "COMPLIANT": "compliant",
                "CONDITIONAL": "conditional",
                "NON_COMPLIANT": "non_compliant",
                "EXEMPT": "exempt",
                "REVIEW_REQUIRED": "review_required",
            },
        ),
    },
)

# Backward-compatible re-exports
ChangeCategory = ComplianceAwareChangeAutomator.ChangeCategory
ComplianceCheck = ComplianceAwareChangeAutomator.ComplianceCheck
ComplianceResult = ComplianceAwareChangeAutomator.ComplianceResult
ComplianceChangeRecord = ComplianceAwareChangeAutomator.Record
ComplianceChangeAnalysis = ComplianceAwareChangeAutomator.Analysis
ComplianceAwareChangeReport = ComplianceAwareChangeAutomator.Report
