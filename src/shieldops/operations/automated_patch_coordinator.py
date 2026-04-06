"""AutomatedPatchCoordinator — coordinate automated patching across infrastructure."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomatedPatchCoordinator = engine(
    "AutomatedPatchCoordinator",
    description="Coordinate automated patching across infrastructure.",
    enums={
        "record_type": EnumDef(
            "AutomatedPatchType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "AutomatedPatchSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "AutomatedPatchLevel",
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
AutomatedPatchType = AutomatedPatchCoordinator.AutomatedPatchType
AutomatedPatchSource = AutomatedPatchCoordinator.AutomatedPatchSource
AutomatedPatchLevel = AutomatedPatchCoordinator.AutomatedPatchLevel
AutomatedPatchRecord = AutomatedPatchCoordinator.Record
AutomatedPatchAnalysis = AutomatedPatchCoordinator.Analysis
AutomatedPatchReport = AutomatedPatchCoordinator.Report
