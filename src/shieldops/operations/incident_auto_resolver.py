"""IncidentAutoResolver — automatically resolve incidents using pattern matching."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IncidentAutoResolver = engine(
    "IncidentAutoResolver",
    description="Automatically resolve incidents using pattern matching.",
    enums={
        "record_type": EnumDef(
            "IncidentAutoType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "IncidentAutoSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "IncidentAutoLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ROUTINE": "routine",
            },
        ),
    },
)

# Backward-compatible re-exports
IncidentAutoType = IncidentAutoResolver.IncidentAutoType
IncidentAutoSource = IncidentAutoResolver.IncidentAutoSource
IncidentAutoLevel = IncidentAutoResolver.IncidentAutoLevel
IncidentAutoRecord = IncidentAutoResolver.Record
IncidentAutoAnalysis = IncidentAutoResolver.Analysis
IncidentAutoReport = IncidentAutoResolver.Report
