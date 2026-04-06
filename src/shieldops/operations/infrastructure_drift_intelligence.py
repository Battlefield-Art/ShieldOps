"""Infrastructure Drift Intelligence — infrastructure drift intelligence and remediation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

InfrastructureDriftIntelligence = engine(
    "InfrastructureDriftIntelligence",
    description="Infrastructure Drift Intelligence — infrastructure drift intelligence and r...",
    enums={
        "drift_type": EnumDef(
            "DriftType",
            {
                "CONFIGURATION": "configuration",
                "VERSION": "version",
                "PERMISSION": "permission",
                "RESOURCE": "resource",
                "NETWORK": "network",
            },
        ),
        "drift_source": EnumDef(
            "DriftSource",
            {
                "TERRAFORM_STATE": "terraform_state",
                "CLOUD_API": "cloud_api",
                "AGENT_SCAN": "agent_scan",
                "AUDIT_LOG": "audit_log",
                "MANUAL": "manual",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "COSMETIC": "cosmetic",
            },
        ),
    },
)

# Backward-compatible re-exports
DriftType = InfrastructureDriftIntelligence.DriftType
DriftSource = InfrastructureDriftIntelligence.DriftSource
DriftSeverity = InfrastructureDriftIntelligence.DriftSeverity
DriftRecord = InfrastructureDriftIntelligence.Record
DriftAnalysis = InfrastructureDriftIntelligence.Analysis
InfrastructureDriftReport = InfrastructureDriftIntelligence.Report
