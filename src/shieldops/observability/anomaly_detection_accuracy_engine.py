"""Anomaly Detection Accuracy Engine — measure precision/recall of anomaly detectors, track fa..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AnomalyDetectionAccuracyEngine = engine(
    "AnomalyDetectionAccuracyEngine",
    description="Measure precision/recall of anomaly detectors, track false positive rates,...",
    enums={
        "detection_method": EnumDef(
            "DetectionMethod",
            {
                "STATISTICAL": "statistical",
                "ML_CLUSTER": "ml_cluster",
                "FORECAST": "forecast",
                "THRESHOLD": "threshold",
                "HYBRID": "hybrid",
            },
        ),
        "anomaly_category": EnumDef(
            "AnomalyCategory",
            {
                "SPIKE": "spike",
                "DIP": "dip",
                "TREND_CHANGE": "trend_change",
                "SEASONAL": "seasonal",
                "NOISE": "noise",
            },
        ),
        "accuracy_outcome": EnumDef(
            "AccuracyOutcome",
            {
                "TRUE_POSITIVE": "true_positive",
                "FALSE_POSITIVE": "false_positive",
                "TRUE_NEGATIVE": "true_negative",
                "FALSE_NEGATIVE": "false_negative",
                "UNVERIFIED": "unverified",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_name", str, ""),
        FieldDef("detection_latency_ms", float, 0.0),
        FieldDef("threshold_value", float, 0.0),
        FieldDef("actual_value", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="confidence_score",
    key_field="detector_name",
)

# Backward-compatible re-exports
DetectionMethod = AnomalyDetectionAccuracyEngine.DetectionMethod
AnomalyCategory = AnomalyDetectionAccuracyEngine.AnomalyCategory
AccuracyOutcome = AnomalyDetectionAccuracyEngine.AccuracyOutcome
AnomalyDetectionAccuracyRecord = AnomalyDetectionAccuracyEngine.Record
AnomalyDetectionAccuracyAnalysis = AnomalyDetectionAccuracyEngine.Analysis
AnomalyDetectionAccuracyReport = AnomalyDetectionAccuracyEngine.Report
