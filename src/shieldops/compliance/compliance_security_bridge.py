"""Compliance Security Bridge — compliance-security bridge linking controls to detections."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ComplianceSecurityBridge = engine(
    "ComplianceSecurityBridge",
    description="Compliance Security Bridge — compliance-security bridge linking controls to...",
    enums={
        "control_framework": EnumDef(
            "ControlFramework",
            {
                "NIST_CSF": "nist_csf",
                "SOC2": "soc2",
                "ISO27001": "iso27001",
                "PCI_DSS": "pci_dss",
                "HIPAA": "hipaa",
            },
        ),
        "bridge_source": EnumDef(
            "BridgeSource",
            {
                "DETECTION_RULES": "detection_rules",
                "SECURITY_CONTROLS": "security_controls",
                "AUDIT_EVIDENCE": "audit_evidence",
                "POLICY": "policy",
                "MANUAL": "manual",
            },
        ),
        "bridge_status": EnumDef(
            "BridgeStatus",
            {
                "MAPPED": "mapped",
                "PARTIAL": "partial",
                "UNMAPPED": "unmapped",
                "OBSOLETE": "obsolete",
                "REVIEW_NEEDED": "review_needed",
            },
        ),
    },
)

# Backward-compatible re-exports
ControlFramework = ComplianceSecurityBridge.ControlFramework
BridgeSource = ComplianceSecurityBridge.BridgeSource
BridgeStatus = ComplianceSecurityBridge.BridgeStatus
BridgeRecord = ComplianceSecurityBridge.Record
BridgeAnalysis = ComplianceSecurityBridge.Analysis
ComplianceSecurityReport = ComplianceSecurityBridge.Report
