"""IntelligentRollbackEngine — execute intelligent rollback decisions based on health metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IntelligentRollbackEngine = engine(
    "IntelligentRollbackEngine",
    description="Execute intelligent rollback decisions based on health metrics.",
    enums={
        "record_type": EnumDef(
            "IntelligentType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "IntelligentSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "IntelligentLevel",
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
IntelligentType = IntelligentRollbackEngine.IntelligentType
IntelligentSource = IntelligentRollbackEngine.IntelligentSource
IntelligentLevel = IntelligentRollbackEngine.IntelligentLevel
IntelligentRecord = IntelligentRollbackEngine.Record
IntelligentAnalysis = IntelligentRollbackEngine.Analysis
IntelligentReport = IntelligentRollbackEngine.Report
