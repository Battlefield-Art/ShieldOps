"""Blast Radius Predictor Engine — predict and track deployment blast radius accuracy."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BlastRadiusPredictorEngine = engine(
    "BlastRadiusPredictorEngine",
    description="Blast Radius Predictor Engine — predict and track blast radius accuracy.",
    enums={
        "prediction_accuracy": EnumDef(
            "PredictionAccuracy",
            {
                "EXACT": "exact",
                "CLOSE": "close",
                "UNDERESTIMATED": "underestimated",
                "OVERESTIMATED": "overestimated",
                "MISSED": "missed",
            },
        ),
        "impact_scope": EnumDef(
            "ImpactScope",
            {
                "SINGLE_SERVICE": "single_service",
                "MULTI_SERVICE": "multi_service",
                "CLUSTER_WIDE": "cluster_wide",
                "REGION_WIDE": "region_wide",
                "GLOBAL": "global",
            },
        ),
        "recovery_speed": EnumDef(
            "RecoverySpeed",
            {
                "INSTANT": "instant",
                "FAST": "fast",
                "MODERATE": "moderate",
                "SLOW": "slow",
                "MANUAL": "manual",
            },
        ),
    },
    record_fields=[
        FieldDef("predicted_services", int, 0),
        FieldDef("actual_services", int, 0),
        FieldDef("recovery_time_min", float, 0.0),
    ],
    key_field="deployment_id",
)

# Backward-compatible re-exports
PredictionAccuracy = BlastRadiusPredictorEngine.PredictionAccuracy
ImpactScope = BlastRadiusPredictorEngine.ImpactScope
RecoverySpeed = BlastRadiusPredictorEngine.RecoverySpeed
BlastRadiusPredictorRecord = BlastRadiusPredictorEngine.Record
BlastRadiusPredictorAnalysis = BlastRadiusPredictorEngine.Analysis
BlastRadiusPredictorReport = BlastRadiusPredictorEngine.Report
