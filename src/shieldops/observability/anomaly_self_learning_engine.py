"""Anomaly Self-Learning Engine Adaptive anomaly detection that incorporates operator feedback..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AnomalySelfLearningEngine = engine(
    "AnomalySelfLearningEngine",
    description="Anomaly Self-Learning Engine Adaptive anomaly detection that incorporates f...",
    enums={
        "feedback_type": EnumDef(
            "FeedbackType",
            {
                "TRUE_POSITIVE": "true_positive",
                "FALSE_POSITIVE": "false_positive",
                "TRUE_NEGATIVE": "true_negative",
                "FALSE_NEGATIVE": "false_negative",
                "UNLABELED": "unlabeled",
            },
        ),
        "model_state": EnumDef(
            "ModelState",
            {
                "TRAINING": "training",
                "ACTIVE": "active",
                "DEGRADED": "degraded",
                "RETRAINING": "retraining",
                "RETIRED": "retired",
            },
        ),
        "sensitivity_level": EnumDef(
            "SensitivityLevel",
            {
                "VERY_HIGH": "very_high",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "VERY_LOW": "very_low",
            },
        ),
    },
    record_fields=[
        FieldDef("predicted_anomaly", bool, False),
        FieldDef("actual_anomaly", bool, False),
        FieldDef("model_version", str, ""),
    ],
    score_field="confidence_score",
    key_field="metric_name",
)

# Backward-compatible re-exports
FeedbackType = AnomalySelfLearningEngine.FeedbackType
ModelState = AnomalySelfLearningEngine.ModelState
SensitivityLevel = AnomalySelfLearningEngine.SensitivityLevel
AnomalyLearningRecord = AnomalySelfLearningEngine.Record
AnomalyLearningAnalysis = AnomalySelfLearningEngine.Analysis
AnomalyLearningReport = AnomalySelfLearningEngine.Report
