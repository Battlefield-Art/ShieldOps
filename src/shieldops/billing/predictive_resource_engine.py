"""Predictive Resource Engine Forecasts resource demand and recommends sizing changes to optim..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PredictiveResourceEngine = engine(
    "PredictiveResourceEngine",
    description="Predictive Resource Engine Forecasts resource demand and recommends sizing...",
    enums={
        "demand_trend": EnumDef(
            "ResourceDemandTrend",
            {
                "GROWING": "growing",
                "STABLE": "stable",
                "DECLINING": "declining",
                "SEASONAL": "seasonal",
                "VOLATILE": "volatile",
            },
        ),
        "sizing_recommendation": EnumDef(
            "SizingRecommendation",
            {
                "DOWNSIZE": "downsize",
                "MAINTAIN": "maintain",
                "UPSIZE": "upsize",
                "RESERVED_INSTANCE": "reserved_instance",
                "SPOT_ELIGIBLE": "spot_eligible",
            },
        ),
        "confidence": EnumDef(
            "PredictionConfidence",
            {
                "VERY_HIGH": "very_high",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("current_usage_pct", float, 0.0),
        FieldDef("predicted_usage_pct", float, 0.0),
        FieldDef("estimated_monthly_cost", float, 0.0),
        FieldDef("potential_savings", float, 0.0),
    ],
    key_field="resource_type",
)

# Backward-compatible re-exports
ResourceDemandTrend = PredictiveResourceEngine.ResourceDemandTrend
SizingRecommendation = PredictiveResourceEngine.SizingRecommendation
PredictionConfidence = PredictiveResourceEngine.PredictionConfidence
ResourceRecord = PredictiveResourceEngine.Record
ResourceAnalysis = PredictiveResourceEngine.Analysis
ResourceReport = PredictiveResourceEngine.Report
