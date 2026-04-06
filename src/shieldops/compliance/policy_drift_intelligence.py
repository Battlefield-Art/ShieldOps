"""Policy Drift Intelligence — policy drift detection and alignment."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PolicyDriftIntelligence = engine(
    "PolicyDriftIntelligence",
    description="Policy Drift Intelligence for drift detection and alignment.",
    enums={
        "drift_type": EnumDef(
            "DriftType",
            {
                "CONFIGURATION": "configuration",
                "PERMISSION": "permission",
                "NETWORK": "network",
                "ENCRYPTION": "encryption",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "drift_source": EnumDef(
            "DriftSource",
            {
                "MANUAL_CHANGE": "manual_change",
                "DEPLOYMENT": "deployment",
                "EXTERNAL": "external",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
DriftType = PolicyDriftIntelligence.DriftType
DriftSeverity = PolicyDriftIntelligence.DriftSeverity
DriftSource = PolicyDriftIntelligence.DriftSource
DriftRecord = PolicyDriftIntelligence.Record
DriftAnalysis = PolicyDriftIntelligence.Analysis
PolicyDriftReport = PolicyDriftIntelligence.Report
