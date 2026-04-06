"""DeploymentIntelligenceEngine Deployment pattern analysis, success prediction, rollback prob..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DeploymentIntelligenceEngine = engine(
    "DeploymentIntelligenceEngine",
    module="operations",  # uses record_item
    description="Deployment pattern analysis with success prediction and rollback scoring.",
    enums={
        "outcome": EnumDef(
            "DeploymentOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL_SUCCESS": "partial_success",
                "ROLLED_BACK": "rolled_back",
                "FAILED": "failed",
                "CANCELLED": "cancelled",
            },
        ),
        "strategy": EnumDef(
            "DeploymentStrategy",
            {
                "ROLLING": "rolling",
                "BLUE_GREEN": "blue_green",
                "CANARY": "canary",
                "RECREATE": "recreate",
                "A_B_TESTING": "a_b_testing",
            },
        ),
        "rollback_risk": EnumDef(
            "RollbackRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
    record_fields=[
        FieldDef("success_probability", float, 0.0),
        FieldDef("rollback_probability", float, 0.0),
        FieldDef("deploy_duration_seconds", float, 0.0),
        FieldDef("change_size_lines", int, 0),
        FieldDef("files_changed", int, 0),
        FieldDef("tests_passed", int, 0),
        FieldDef("tests_failed", int, 0),
        FieldDef("environment", str, ""),
    ],
)

# Backward-compatible re-exports
DeploymentOutcome = DeploymentIntelligenceEngine.DeploymentOutcome
DeploymentStrategy = DeploymentIntelligenceEngine.DeploymentStrategy
RollbackRisk = DeploymentIntelligenceEngine.RollbackRisk
DeploymentIntelligenceRecord = DeploymentIntelligenceEngine.Record
DeploymentIntelligenceAnalysis = DeploymentIntelligenceEngine.Analysis
DeploymentIntelligenceReport = DeploymentIntelligenceEngine.Report
