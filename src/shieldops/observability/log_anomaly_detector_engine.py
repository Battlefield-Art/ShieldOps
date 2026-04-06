"""Log Anomaly Detector Engine — track log anomaly detection accuracy."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LogAnomalyDetectorEngine = engine(
    "LogAnomalyDetectorEngine",
    description="Track log anomaly detection accuracy across services.",
    enums={
        "anomaly_method": EnumDef(
            "AnomalyMethod",
            {
                "STATISTICAL": "statistical",
                "PATTERN_MATCH": "pattern_match",
                "ML_CLUSTERING": "ml_clustering",
                "FREQUENCY": "frequency",
                "KEYWORD": "keyword",
            },
        ),
        "log_category": EnumDef(
            "LogCategory",
            {
                "ERROR": "error",
                "WARNING": "warning",
                "SECURITY": "security",
                "PERFORMANCE": "performance",
                "AUDIT": "audit",
            },
        ),
        "detection_outcome": EnumDef(
            "DetectionOutcome",
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
        FieldDef("log_volume", int, 0),
        FieldDef("anomaly_count", int, 0),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="confidence_score",
    key_field="service_id",
)

# Backward-compatible re-exports
AnomalyMethod = LogAnomalyDetectorEngine.AnomalyMethod
LogCategory = LogAnomalyDetectorEngine.LogCategory
DetectionOutcome = LogAnomalyDetectorEngine.DetectionOutcome
LogAnomalyDetectorRecord = LogAnomalyDetectorEngine.Record
LogAnomalyDetectorAnalysis = LogAnomalyDetectorEngine.Analysis
LogAnomalyDetectorReport = LogAnomalyDetectorEngine.Report
