"""Helm Deployment Intelligence Engine — assess upgrade readiness, detect helm misconfiguratio..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

HelmDeploymentIntelligenceEngine = engine(
    "HelmDeploymentIntelligenceEngine",
    description="Assess upgrade readiness, detect helm misconfigurations, compare deployment...",
    enums={
        "deployment_mode": EnumDef(
            "DeploymentMode",
            {
                "DAEMONSET": "daemonset",
                "DEPLOYMENT": "deployment",
                "STATEFULSET": "statefulset",
                "SIDECAR": "sidecar",
            },
        ),
        "chart_health": EnumDef(
            "ChartHealth",
            {
                "UP_TO_DATE": "up_to_date",
                "MINOR_BEHIND": "minor_behind",
                "MAJOR_BEHIND": "major_behind",
                "UNSUPPORTED": "unsupported",
            },
        ),
        "misconfig_risk": EnumDef(
            "MisconfigRisk",
            {
                "NONE": "none",
                "PERFORMANCE": "performance",
                "DATA_LOSS": "data_loss",
                "SECURITY": "security",
            },
        ),
    },
    record_fields=[
        FieldDef("chart_version", str, ""),
        FieldDef("deployed_version", str, ""),
        FieldDef("replica_count", int, 1),
        FieldDef("misconfig_count", int, 0),
        FieldDef("upgrade_blocking_issues", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="release_name",
)

# Backward-compatible re-exports
DeploymentMode = HelmDeploymentIntelligenceEngine.DeploymentMode
ChartHealth = HelmDeploymentIntelligenceEngine.ChartHealth
MisconfigRisk = HelmDeploymentIntelligenceEngine.MisconfigRisk
HelmDeploymentRecord = HelmDeploymentIntelligenceEngine.Record
HelmDeploymentAnalysis = HelmDeploymentIntelligenceEngine.Analysis
HelmDeploymentReport = HelmDeploymentIntelligenceEngine.Report
