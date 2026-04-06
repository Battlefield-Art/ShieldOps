"""RemediationImpactPredictor — predict the impact of remediation actions before execution."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RemediationImpactPredictor = engine(
    "RemediationImpactPredictor",
    description="Predict the impact of remediation actions before execution.",
    enums={
        "record_type": EnumDef(
            "RemediationType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "RemediationSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "RemediationLevel",
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
RemediationType = RemediationImpactPredictor.RemediationType
RemediationSource = RemediationImpactPredictor.RemediationSource
RemediationLevel = RemediationImpactPredictor.RemediationLevel
RemediationRecord = RemediationImpactPredictor.Record
RemediationAnalysis = RemediationImpactPredictor.Analysis
RemediationReport = RemediationImpactPredictor.Report
