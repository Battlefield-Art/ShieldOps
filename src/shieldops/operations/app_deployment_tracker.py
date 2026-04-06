"""App Deployment Tracker — track deployments, health, and rollbacks."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AppDeploymentTracker = engine(
    "AppDeploymentTracker",
    description="Track application deployments, health, and rollbacks.",
    enums={
        "stage": EnumDef(
            "DeployStage",
            {
                "BUILDING": "building",
                "TESTING": "testing",
                "STAGING": "staging",
                "CANARY": "canary",
                "PRODUCTION": "production",
            },
        ),
        "outcome": EnumDef(
            "DeployOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL_SUCCESS": "partial_success",
                "FAILED": "failed",
                "ROLLED_BACK": "rolled_back",
                "IN_PROGRESS": "in_progress",
            },
        ),
        "rollback_reason": EnumDef(
            "RollbackReason",
            {
                "ERROR_RATE_SPIKE": "error_rate_spike",
                "LATENCY_REGRESSION": "latency_regression",
                "HEALTH_CHECK_FAIL": "health_check_fail",
                "MANUAL_DECISION": "manual_decision",
                "SLO_BREACH": "slo_breach",
            },
        ),
    },
    record_fields=[
        FieldDef("version", str, ""),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("deployer", str, ""),
    ],
    score_field="health_score",
    key_field="app_name",
)

# Backward-compatible re-exports
DeployStage = AppDeploymentTracker.DeployStage
DeployOutcome = AppDeploymentTracker.DeployOutcome
RollbackReason = AppDeploymentTracker.RollbackReason
DeploymentRecord = AppDeploymentTracker.Record
DeploymentAnalysis = AppDeploymentTracker.Analysis
DeploymentReport = AppDeploymentTracker.Report
