"""ChangeRiskAutoAssessor — automatically assess change risk for remediation actions."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ChangeRiskAutoAssessor = engine(
    "ChangeRiskAutoAssessor",
    description="Automatically assess change risk for remediation actions.",
    enums={
        "record_type": EnumDef(
            "ChangeRiskAutoType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "ChangeRiskAutoSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "ChangeRiskAutoLevel",
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
ChangeRiskAutoType = ChangeRiskAutoAssessor.ChangeRiskAutoType
ChangeRiskAutoSource = ChangeRiskAutoAssessor.ChangeRiskAutoSource
ChangeRiskAutoLevel = ChangeRiskAutoAssessor.ChangeRiskAutoLevel
ChangeRiskAutoRecord = ChangeRiskAutoAssessor.Record
ChangeRiskAutoAnalysis = ChangeRiskAutoAssessor.Analysis
ChangeRiskAutoReport = ChangeRiskAutoAssessor.Report
