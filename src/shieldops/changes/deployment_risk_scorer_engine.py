"""Deployment Risk Scorer Engine — score deployment risk using historical patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DeploymentRiskScorerEngine = engine(
    "DeploymentRiskScorerEngine",
    description="Deployment Risk Scorer Engine — score deployment risk using historical patt...",
    enums={
        "deployment_type": EnumDef(
            "DeploymentType",
            {
                "ROLLING": "rolling",
                "BLUE_GREEN": "blue_green",
                "CANARY": "canary",
                "RECREATE": "recreate",
                "FEATURE_FLAG": "feature_flag",
            },
        ),
        "risk_factor": EnumDef(
            "RiskFactor",
            {
                "FRIDAY_DEPLOY": "friday_deploy",
                "LARGE_DIFF": "large_diff",
                "DB_MIGRATION": "db_migration",
                "PROD_ENV": "prod_env",
                "NEW_SERVICE": "new_service",
                "HOTFIX": "hotfix",
            },
        ),
        "deployment_outcome": EnumDef(
            "DeploymentOutcome",
            {
                "SUCCESS": "success",
                "ROLLBACK": "rollback",
                "PARTIAL_FAILURE": "partial_failure",
                "FULL_FAILURE": "full_failure",
                "DELAYED": "delayed",
            },
        ),
    },
    record_fields=[
        FieldDef("files_changed", int, 0),
        FieldDef("services_affected", int, 0),
    ],
    score_field="risk_score",
    key_field="deployment_id",
)

# Backward-compatible re-exports
DeploymentType = DeploymentRiskScorerEngine.DeploymentType
RiskFactor = DeploymentRiskScorerEngine.RiskFactor
DeploymentOutcome = DeploymentRiskScorerEngine.DeploymentOutcome
DeploymentRiskRecord = DeploymentRiskScorerEngine.Record
DeploymentRiskAnalysis = DeploymentRiskScorerEngine.Analysis
DeploymentRiskReport = DeploymentRiskScorerEngine.Report
