"""DependencyUpgradeEngine Dependency upgrade planning, version lag tracking, breaking change..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DependencyUpgradeEngine = engine(
    "DependencyUpgradeEngine",
    module="operations",  # uses record_item
    description="Dependency upgrade planning with version lag tracking.",
    enums={
        "upgrade_urgency": EnumDef(
            "UpgradeUrgency",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
        "upgrade_type": EnumDef(
            "UpgradeType",
            {
                "MAJOR": "major",
                "MINOR": "minor",
                "PATCH": "patch",
                "SECURITY": "security",
                "TRANSITIVE": "transitive",
            },
        ),
        "upgrade_risk": EnumDef(
            "UpgradeRisk",
            {
                "BREAKING": "breaking",
                "POTENTIALLY_BREAKING": "potentially_breaking",
                "SAFE": "safe",
                "UNKNOWN": "unknown",
                "TESTED": "tested",
            },
        ),
    },
)

# Backward-compatible re-exports
UpgradeUrgency = DependencyUpgradeEngine.UpgradeUrgency
UpgradeType = DependencyUpgradeEngine.UpgradeType
UpgradeRisk = DependencyUpgradeEngine.UpgradeRisk
DependencyUpgradeRecord = DependencyUpgradeEngine.Record
DependencyUpgradeAnalysis = DependencyUpgradeEngine.Analysis
DependencyUpgradeReport = DependencyUpgradeEngine.Report
