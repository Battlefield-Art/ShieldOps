"""Adaptive Threshold Engine Dynamically adjusts alert thresholds based on seasonality, traffi..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdaptiveThresholdEngine = engine(
    "AdaptiveThresholdEngine",
    description="Adaptive Threshold Engine Dynamically adjusts alert thresholds based on sea...",
    enums={
        "strategy": EnumDef(
            "ThresholdStrategy",
            {
                "STATIC": "static",
                "SEASONAL": "seasonal",
                "PERCENTILE": "percentile",
                "ML_ADAPTIVE": "ml_adaptive",
                "TRAFFIC_AWARE": "traffic_aware",
            },
        ),
        "adjustment_reason": EnumDef(
            "AdjustmentReason",
            {
                "SEASONALITY": "seasonality",
                "DEPLOYMENT": "deployment",
                "TRAFFIC_SPIKE": "traffic_spike",
                "DRIFT": "drift",
                "MANUAL": "manual",
            },
        ),
        "health": EnumDef(
            "ThresholdHealth",
            {
                "OPTIMAL": "optimal",
                "NEEDS_TUNING": "needs_tuning",
                "STALE": "stale",
                "MISCONFIGURED": "misconfigured",
            },
        ),
    },
    record_fields=[
        FieldDef("current_threshold", float, 0.0),
        FieldDef("recommended_threshold", float, 0.0),
        FieldDef("false_positive_rate", float, 0.0),
        FieldDef("false_negative_rate", float, 0.0),
    ],
    key_field="metric_name",
)

# Backward-compatible re-exports
ThresholdStrategy = AdaptiveThresholdEngine.ThresholdStrategy
AdjustmentReason = AdaptiveThresholdEngine.AdjustmentReason
ThresholdHealth = AdaptiveThresholdEngine.ThresholdHealth
ThresholdRecord = AdaptiveThresholdEngine.Record
ThresholdAnalysis = AdaptiveThresholdEngine.Analysis
ThresholdReport = AdaptiveThresholdEngine.Report
