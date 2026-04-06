"""Action Recommendation Engine — recommend response actions."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ActionRecommendationEngine = engine(
    "ActionRecommendationEngine",
    description="Generate and track action recommendations.",
    enums={
        "category": EnumDef(
            "ActionCategory",
            {
                "CONTAIN": "contain",
                "INVESTIGATE": "investigate",
                "REMEDIATE": "remediate",
                "MONITOR": "monitor",
                "ESCALATE": "escalate",
            },
        ),
        "basis": EnumDef(
            "RecommendationBasis",
            {
                "PATTERN_MATCH": "pattern_match",
                "LLM_REASONING": "llm_reasoning",
                "HISTORICAL": "historical",
                "POLICY": "policy",
            },
        ),
        "effectiveness": EnumDef(
            "EffectivenessScore",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("action_description", str, ""),
        FieldDef("confidence", float, 0.0),
        FieldDef("accepted", str, None),
        FieldDef("outcome_feedback", str, ""),
    ],
    key_field="situation_id",
)

# Backward-compatible re-exports
ActionCategory = ActionRecommendationEngine.ActionCategory
RecommendationBasis = ActionRecommendationEngine.RecommendationBasis
EffectivenessScore = ActionRecommendationEngine.EffectivenessScore
RecommendationRecord = ActionRecommendationEngine.Record
RecommendationAnalysis = ActionRecommendationEngine.Analysis
RecommendationReport = ActionRecommendationEngine.Report
