"""Autonomous Compliance Engine — autonomous compliance assessment and remediation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousComplianceEngine = engine(
    "AutonomousComplianceEngine",
    description="Autonomous Compliance Engine for compliance assessment and remediation.",
    enums={
        "compliance_action": EnumDef(
            "ComplianceAction",
            {
                "ASSESS": "assess",
                "REMEDIATE": "remediate",
                "VERIFY": "verify",
                "REPORT": "report",
            },
        ),
        "framework_scope": EnumDef(
            "FrameworkScope",
            {
                "SOC2": "soc2",
                "HIPAA": "hipaa",
                "PCI": "pci",
                "ISO27001": "iso27001",
            },
        ),
        "automation_level": EnumDef(
            "AutomationLevel",
            {
                "MANUAL": "manual",
                "ASSISTED": "assisted",
                "AUTOMATED": "automated",
                "AUTONOMOUS": "autonomous",
            },
        ),
    },
)

# Backward-compatible re-exports
ComplianceAction = AutonomousComplianceEngine.ComplianceAction
FrameworkScope = AutonomousComplianceEngine.FrameworkScope
AutomationLevel = AutonomousComplianceEngine.AutomationLevel
ComplianceRecord = AutonomousComplianceEngine.Record
ComplianceAnalysis = AutonomousComplianceEngine.Analysis
AutonomousComplianceReport = AutonomousComplianceEngine.Report
