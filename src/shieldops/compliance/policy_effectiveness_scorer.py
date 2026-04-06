"""Policy Effectiveness Scorer compute policy effectiveness score, detect ineffective policies..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PolicyEffectivenessScorer = engine(
    "PolicyEffectivenessScorer",
    description="Compute policy effectiveness score, detect ineffective policies, rank by vi...",
    enums={
        "effectiveness_rating": EnumDef(
            "EffectivenessRating",
            {
                "HIGHLY_EFFECTIVE": "highly_effective",
                "EFFECTIVE": "effective",
                "PARTIALLY_EFFECTIVE": "partially_effective",
                "INEFFECTIVE": "ineffective",
            },
        ),
        "policy_type": EnumDef(
            "PolicyType",
            {
                "ACCESS": "access",
                "DATA": "data",
                "NETWORK": "network",
                "OPERATIONAL": "operational",
            },
        ),
        "violation_trend": EnumDef(
            "ViolationTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "ZERO": "zero",
            },
        ),
    },
    record_fields=[
        FieldDef("violation_count", int, 0),
        FieldDef("compliance_rate", float, 100.0),
        FieldDef("description", str, ""),
    ],
    score_field="effectiveness_score",
    key_field="policy_id",
)

# Backward-compatible re-exports
EffectivenessRating = PolicyEffectivenessScorer.EffectivenessRating
PolicyType = PolicyEffectivenessScorer.PolicyType
ViolationTrend = PolicyEffectivenessScorer.ViolationTrend
PolicyEffectivenessRecord = PolicyEffectivenessScorer.Record
PolicyEffectivenessAnalysis = PolicyEffectivenessScorer.Analysis
PolicyEffectivenessReport = PolicyEffectivenessScorer.Report
