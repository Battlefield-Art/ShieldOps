"""Alert Lifecycle Manager — track alerts through their full lifecycle phases."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AlertLifecycleManager = engine(
    "AlertLifecycleManager",
    description="Track alerts through their full lifecycle phases.",
    enums={
        "alert_phase": EnumDef(
            "AlertPhase",
            {
                "CREATED": "created",
                "TRIAGED": "triaged",
                "INVESTIGATED": "investigated",
                "RESOLVED": "resolved",
                "CLOSED": "closed",
            },
        ),
        "alert_priority": EnumDef(
            "AlertPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
        "alert_source": EnumDef(
            "AlertSource",
            {
                "SIEM": "siem",
                "EDR": "edr",
                "NDR": "ndr",
                "CLOUD": "cloud",
                "CUSTOM": "custom",
            },
        ),
    },
    score_field="lifecycle_score",
    key_field="alert_name",
)

# Backward-compatible re-exports
AlertPhase = AlertLifecycleManager.AlertPhase
AlertPriority = AlertLifecycleManager.AlertPriority
AlertSource = AlertLifecycleManager.AlertSource
AlertLifecycleRecord = AlertLifecycleManager.Record
AlertLifecycleAnalysis = AlertLifecycleManager.Analysis
AlertLifecycleReport = AlertLifecycleManager.Report
