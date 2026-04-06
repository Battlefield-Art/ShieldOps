"""Infrastructure Change Risk Scorer compute change risk scores, detect high risk patterns, ra..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InfrastructureChangeRiskScorer = engine(
    "InfrastructureChangeRiskScorer",
    module="operations",  # uses record_item
    description="Compute change risk scores, detect high risk patterns, rank changes by roll...",
    enums={
        "change_scope": EnumDef(
            "ChangeScope",
            {
                "SINGLE_RESOURCE": "single_resource",
                "MODULE": "module",
                "STACK": "stack",
                "CROSS_STACK": "cross_stack",
            },
        ),
        "risk_factor": EnumDef(
            "RiskFactor",
            {
                "BLAST_RADIUS": "blast_radius",
                "REVERSIBILITY": "reversibility",
                "DEPENDENCY": "dependency",
                "TIMING": "timing",
            },
        ),
        "rollback_complexity": EnumDef(
            "RollbackComplexity",
            {
                "TRIVIAL": "trivial",
                "MODERATE": "moderate",
                "COMPLEX": "complex",
                "IMPOSSIBLE": "impossible",
            },
        ),
    },
    record_fields=[
        FieldDef("change_name", str, ""),
        FieldDef("affected_services", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="risk_score",
    key_field="change_id",
)

# Backward-compatible re-exports
ChangeScope = InfrastructureChangeRiskScorer.ChangeScope
RiskFactor = InfrastructureChangeRiskScorer.RiskFactor
RollbackComplexity = InfrastructureChangeRiskScorer.RollbackComplexity
ChangeRiskRecord = InfrastructureChangeRiskScorer.Record
ChangeRiskAnalysis = InfrastructureChangeRiskScorer.Analysis
ChangeRiskReport = InfrastructureChangeRiskScorer.Report
