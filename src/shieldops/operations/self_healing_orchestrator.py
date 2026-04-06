"""SelfHealingOrchestrator — orchestrate self-healing workflows for infrastructure issues."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SelfHealingOrchestrator = engine(
    "SelfHealingOrchestrator",
    description="Orchestrate self-healing workflows for infrastructure issues.",
    enums={
        "record_type": EnumDef(
            "SelfHealingType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "SelfHealingSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "SelfHealingLevel",
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
SelfHealingType = SelfHealingOrchestrator.SelfHealingType
SelfHealingSource = SelfHealingOrchestrator.SelfHealingSource
SelfHealingLevel = SelfHealingOrchestrator.SelfHealingLevel
SelfHealingRecord = SelfHealingOrchestrator.Record
SelfHealingAnalysis = SelfHealingOrchestrator.Analysis
SelfHealingReport = SelfHealingOrchestrator.Report
