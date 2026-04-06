"""Deployment Reliability Impact Engine compute deployment reliability delta, detect reliabili..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DeploymentReliabilityImpactEngine = engine(
    "DeploymentReliabilityImpactEngine",
    module="operations",  # uses record_item
    description="Compute deployment reliability delta, detect reliability degrading deploys,...",
    enums={
        "reliability_impact": EnumDef(
            "ReliabilityImpact",
            {
                "POSITIVE": "positive",
                "NEUTRAL": "neutral",
                "NEGATIVE": "negative",
                "SEVERE": "severe",
            },
        ),
        "deployment_type": EnumDef(
            "DeploymentType",
            {
                "STANDARD": "standard",
                "CANARY": "canary",
                "BLUE_GREEN": "blue_green",
                "ROLLING": "rolling",
            },
        ),
        "impact_window": EnumDef(
            "ImpactWindow",
            {
                "IMMEDIATE": "immediate",
                "SHORT_TERM": "short_term",
                "MEDIUM_TERM": "medium_term",
                "LONG_TERM": "long_term",
            },
        ),
    },
    record_fields=[
        FieldDef("post_deploy_score", float, 0.0),
        FieldDef("delta", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="pre_deploy_score",
    key_field="deployment_id",
)

# Backward-compatible re-exports
ReliabilityImpact = DeploymentReliabilityImpactEngine.ReliabilityImpact
DeploymentType = DeploymentReliabilityImpactEngine.DeploymentType
ImpactWindow = DeploymentReliabilityImpactEngine.ImpactWindow
DeploymentReliabilityRecord = DeploymentReliabilityImpactEngine.Record
DeploymentReliabilityAnalysis = DeploymentReliabilityImpactEngine.Analysis
DeploymentReliabilityReport = DeploymentReliabilityImpactEngine.Report
