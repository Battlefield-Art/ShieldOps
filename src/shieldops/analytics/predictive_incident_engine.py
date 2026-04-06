"""PredictiveIncidentEngine — Predict incidents based on historical patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PredictiveIncidentEngine = engine(
    "PredictiveIncidentEngine",
    description="Predict incidents before they happen based on historical patterns.",
    enums={
        "horizon": EnumDef(
            "PredictionHorizon",
            {
                "MINUTES": "minutes",
                "HOURS": "hours",
                "DAYS": "days",
            },
        ),
        "indicator": EnumDef(
            "IndicatorType",
            {
                "METRIC_ANOMALY": "metric_anomaly",
                "LOG_PATTERN": "log_pattern",
                "DEPLOYMENT_CHANGE": "deployment_change",
                "CAPACITY_TREND": "capacity_trend",
            },
        ),
        "confidence": EnumDef(
            "PredictionConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("prediction_accuracy", float, 0.0),
        FieldDef("indicator_count", int, 0),
    ],
)

# Backward-compatible re-exports
PredictionHorizon = PredictiveIncidentEngine.PredictionHorizon
IndicatorType = PredictiveIncidentEngine.IndicatorType
PredictionConfidence = PredictiveIncidentEngine.PredictionConfidence
PredictiveIncidentRecord = PredictiveIncidentEngine.Record
PredictiveIncidentAnalysis = PredictiveIncidentEngine.Analysis
PredictiveIncidentReport = PredictiveIncidentEngine.Report
