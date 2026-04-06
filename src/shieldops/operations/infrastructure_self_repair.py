"""InfrastructureSelfRepair — self-repair infrastructure issues with automated diagnostics."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

InfrastructureSelfRepair = engine(
    "InfrastructureSelfRepair",
    description="Self-repair infrastructure issues with automated diagnostics.",
    enums={
        "record_type": EnumDef(
            "InfrastructureType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "InfrastructureSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "InfrastructureLevel",
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
InfrastructureType = InfrastructureSelfRepair.InfrastructureType
InfrastructureSource = InfrastructureSelfRepair.InfrastructureSource
InfrastructureLevel = InfrastructureSelfRepair.InfrastructureLevel
InfrastructureRecord = InfrastructureSelfRepair.Record
InfrastructureAnalysis = InfrastructureSelfRepair.Analysis
InfrastructureReport = InfrastructureSelfRepair.Report
