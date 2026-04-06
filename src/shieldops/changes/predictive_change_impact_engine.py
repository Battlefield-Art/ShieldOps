"""PredictiveChangeImpactEngine — predictive change impact engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveChangeImpactEngine = engine(
    "PredictiveChangeImpactEngine",
    module="operations",  # uses record_item
    description="Predictive Change Impact Engine.",
    enums={
        "change_type": EnumDef(
            "ChangeType",
            {
                "CODE_DEPLOY": "code_deploy",
                "CONFIG_CHANGE": "config_change",
                "INFRA_CHANGE": "infra_change",
                "DEPENDENCY_UPDATE": "dependency_update",
                "POLICY_CHANGE": "policy_change",
            },
        ),
        "impact_scope": EnumDef(
            "ImpactScope",
            {
                "SERVICE": "service",
                "TEAM": "team",
                "DEPARTMENT": "department",
                "ORGANIZATION": "organization",
                "EXTERNAL": "external",
            },
        ),
        "impact_likelihood": EnumDef(
            "ImpactLikelihood",
            {
                "CERTAIN": "certain",
                "LIKELY": "likely",
                "POSSIBLE": "possible",
                "UNLIKELY": "unlikely",
                "RARE": "rare",
            },
        ),
    },
)

# Backward-compatible re-exports
ChangeType = PredictiveChangeImpactEngine.ChangeType
ImpactScope = PredictiveChangeImpactEngine.ImpactScope
ImpactLikelihood = PredictiveChangeImpactEngine.ImpactLikelihood
PredictiveChangeImpactEngineRecord = PredictiveChangeImpactEngine.Record
PredictiveChangeImpactEngineAnalysis = PredictiveChangeImpactEngine.Analysis
PredictiveChangeImpactEngineReport = PredictiveChangeImpactEngine.Report
