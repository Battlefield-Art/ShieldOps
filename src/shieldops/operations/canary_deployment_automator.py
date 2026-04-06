"""CanaryDeploymentAutomator — automate canary deployment strategies and health validation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CanaryDeploymentAutomator = engine(
    "CanaryDeploymentAutomator",
    description="Automate canary deployment strategies and health validation.",
    enums={
        "record_type": EnumDef(
            "CanaryDeploymentType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "CanaryDeploymentSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "CanaryDeploymentLevel",
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
CanaryDeploymentType = CanaryDeploymentAutomator.CanaryDeploymentType
CanaryDeploymentSource = CanaryDeploymentAutomator.CanaryDeploymentSource
CanaryDeploymentLevel = CanaryDeploymentAutomator.CanaryDeploymentLevel
CanaryDeploymentRecord = CanaryDeploymentAutomator.Record
CanaryDeploymentAnalysis = CanaryDeploymentAutomator.Analysis
CanaryDeploymentReport = CanaryDeploymentAutomator.Report
