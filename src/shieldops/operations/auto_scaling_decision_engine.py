"""AutoScalingDecisionEngine — make intelligent auto-scaling decisions based on workload patte..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutoScalingDecisionEngine = engine(
    "AutoScalingDecisionEngine",
    description="Make intelligent auto-scaling decisions based on workload patterns.",
    enums={
        "record_type": EnumDef(
            "AutoScalingType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "AutoScalingSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "AutoScalingLevel",
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
AutoScalingType = AutoScalingDecisionEngine.AutoScalingType
AutoScalingSource = AutoScalingDecisionEngine.AutoScalingSource
AutoScalingLevel = AutoScalingDecisionEngine.AutoScalingLevel
AutoScalingRecord = AutoScalingDecisionEngine.Record
AutoScalingAnalysis = AutoScalingDecisionEngine.Analysis
AutoScalingReport = AutoScalingDecisionEngine.Report
