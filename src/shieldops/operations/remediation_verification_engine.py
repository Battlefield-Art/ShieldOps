"""RemediationVerificationEngine — verify remediation actions achieved their intended results."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RemediationVerificationEngine = engine(
    "RemediationVerificationEngine",
    description="Verify remediation actions achieved their intended results.",
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
RemediationType = RemediationVerificationEngine.RemediationType
RemediationSource = RemediationVerificationEngine.RemediationSource
RemediationLevel = RemediationVerificationEngine.RemediationLevel
RemediationRecord = RemediationVerificationEngine.Record
RemediationAnalysis = RemediationVerificationEngine.Analysis
RemediationReport = RemediationVerificationEngine.Report
