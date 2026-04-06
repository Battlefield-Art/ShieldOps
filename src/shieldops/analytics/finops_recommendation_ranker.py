"""FinOps Recommendation Ranker rank by ROI-adjusted effort, assess recommendation risk, track..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FinopsRecommendationRanker = engine(
    "FinopsRecommendationRanker",
    description="Rank by ROI-adjusted effort, assess risk, track adoption.",
    enums={
        "recommendation_type": EnumDef(
            "RecommendationType",
            {
                "RIGHTSIZING": "rightsizing",
                "RESERVATION": "reservation",
                "ELIMINATION": "elimination",
                "OPTIMIZATION": "optimization",
            },
        ),
        "risk_level": EnumDef(
            "RiskLevel",
            {
                "MINIMAL": "minimal",
                "LOW": "low",
                "MODERATE": "moderate",
                "HIGH": "high",
            },
        ),
        "adoption_status": EnumDef(
            "AdoptionStatus",
            {
                "IMPLEMENTED": "implemented",
                "IN_PROGRESS": "in_progress",
                "DEFERRED": "deferred",
                "REJECTED": "rejected",
            },
        ),
    },
    record_fields=[
        FieldDef("estimated_savings", float, 0.0),
        FieldDef("effort_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="recommendation_id",
)

# Backward-compatible re-exports
RecommendationType = FinopsRecommendationRanker.RecommendationType
RiskLevel = FinopsRecommendationRanker.RiskLevel
AdoptionStatus = FinopsRecommendationRanker.AdoptionStatus
RecommendationRecord = FinopsRecommendationRanker.Record
RecommendationAnalysis = FinopsRecommendationRanker.Analysis
RecommendationReport = FinopsRecommendationRanker.Report
