"""ActiveDirectoryThreatMonitor — monitor active directory for threats and suspicious changes."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ActiveDirectoryThreatMonitor = engine(
    "ActiveDirectoryThreatMonitor",
    description="Monitor Active Directory for threats and suspicious changes.",
    enums={
        "record_type": EnumDef(
            "ActiveDirectoryType",
            {
                "VULNERABILITY": "vulnerability",
                "MISCONFIGURATION": "misconfiguration",
                "THREAT": "threat",
                "POLICY_VIOLATION": "policy_violation",
                "ANOMALY": "anomaly",
            },
        ),
        "source": EnumDef(
            "ActiveDirectorySource",
            {
                "SCANNER": "scanner",
                "SIEM": "siem",
                "EDR": "edr",
                "CLOUD_AUDIT": "cloud_audit",
                "MANUAL": "manual",
            },
        ),
        "level": EnumDef(
            "ActiveDirectoryLevel",
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
ActiveDirectoryType = ActiveDirectoryThreatMonitor.ActiveDirectoryType
ActiveDirectorySource = ActiveDirectoryThreatMonitor.ActiveDirectorySource
ActiveDirectoryLevel = ActiveDirectoryThreatMonitor.ActiveDirectoryLevel
ActiveDirectoryRecord = ActiveDirectoryThreatMonitor.Record
ActiveDirectoryAnalysis = ActiveDirectoryThreatMonitor.Analysis
ActiveDirectoryReport = ActiveDirectoryThreatMonitor.Report
