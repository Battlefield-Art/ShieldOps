"""AdversaryTacticsProfiler — profile adversary tactics, techniques, and procedures."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdversaryTacticsProfiler = engine(
    "AdversaryTacticsProfiler",
    description="Profile adversary tactics, techniques, and procedures.",
    enums={
        "record_type": EnumDef(
            "AdversaryTacticsType",
            {
                "VULNERABILITY": "vulnerability",
                "MISCONFIGURATION": "misconfiguration",
                "THREAT": "threat",
                "POLICY_VIOLATION": "policy_violation",
                "ANOMALY": "anomaly",
            },
        ),
        "source": EnumDef(
            "AdversaryTacticsSource",
            {
                "SCANNER": "scanner",
                "SIEM": "siem",
                "EDR": "edr",
                "CLOUD_AUDIT": "cloud_audit",
                "MANUAL": "manual",
            },
        ),
        "level": EnumDef(
            "AdversaryTacticsLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info",
            },
        ),
    },
)

# Backward-compatible re-exports
AdversaryTacticsType = AdversaryTacticsProfiler.AdversaryTacticsType
AdversaryTacticsSource = AdversaryTacticsProfiler.AdversaryTacticsSource
AdversaryTacticsLevel = AdversaryTacticsProfiler.AdversaryTacticsLevel
AdversaryTacticsRecord = AdversaryTacticsProfiler.Record
AdversaryTacticsAnalysis = AdversaryTacticsProfiler.Analysis
AdversaryTacticsReport = AdversaryTacticsProfiler.Report
