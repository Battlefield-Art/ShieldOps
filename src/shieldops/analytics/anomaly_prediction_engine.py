"""AnomalyPredictionEngine — anomaly prediction engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AnomalyPredictionEngine = engine(
    "AnomalyPredictionEngine",
    module="operations",  # uses record_item
    description="Anomaly Prediction Engine.",
    enums={
        "anomaly_type": EnumDef(
            "AnomalyType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "BEHAVIORAL": "behavioral",
                "COMPOSITE": "composite",
            },
        ),
        "prediction_model": EnumDef(
            "PredictionModel",
            {
                "STATISTICAL": "statistical",
                "ML_SUPERVISED": "ml_supervised",
                "ML_UNSUPERVISED": "ml_unsupervised",
                "DEEP_LEARNING": "deep_learning",
                "ENSEMBLE": "ensemble",
            },
        ),
        "anomaly_impact": EnumDef(
            "AnomalyImpact",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
)

# Backward-compatible re-exports
AnomalyType = AnomalyPredictionEngine.AnomalyType
PredictionModel = AnomalyPredictionEngine.PredictionModel
AnomalyImpact = AnomalyPredictionEngine.AnomalyImpact
AnomalyPredictionEngineRecord = AnomalyPredictionEngine.Record
AnomalyPredictionEngineAnalysis = AnomalyPredictionEngine.Analysis
AnomalyPredictionEngineReport = AnomalyPredictionEngine.Report
