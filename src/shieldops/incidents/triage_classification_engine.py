"""Triage Classification Engine — track incident triage classification accuracy."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TriageClassificationEngine = engine(
    "TriageClassificationEngine",
    description="Triage Classification Engine — track incident triage classification accuracy.",
    enums={
        "classification_method": EnumDef(
            "ClassificationMethod",
            {
                "ML_MODEL": "ml_model",
                "KEYWORD": "keyword",
                "HISTORICAL": "historical",
                "MANUAL": "manual",
                "LLM_ASSISTED": "llm_assisted",
            },
        ),
        "severity_accuracy": EnumDef(
            "SeverityAccuracy",
            {
                "EXACT": "exact",
                "ONE_OFF": "one_off",
                "TWO_OFF": "two_off",
                "MISSED": "missed",
                "OVERCLASSIFIED": "overclassified",
            },
        ),
        "triage_outcome": EnumDef(
            "TriageOutcome",
            {
                "AUTO_RESOLVED": "auto_resolved",
                "ESCALATED": "escalated",
                "ROUTED": "routed",
                "DEDUPLICATED": "deduplicated",
                "FALSE_POSITIVE": "false_positive",
            },
        ),
    },
    record_fields=[
        FieldDef("predicted_severity", str, ""),
        FieldDef("actual_severity", str, ""),
        FieldDef("triage_time_ms", float, 0.0),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
ClassificationMethod = TriageClassificationEngine.ClassificationMethod
SeverityAccuracy = TriageClassificationEngine.SeverityAccuracy
TriageOutcome = TriageClassificationEngine.TriageOutcome
TriageClassificationRecord = TriageClassificationEngine.Record
TriageClassificationAnalysis = TriageClassificationEngine.Analysis
TriageClassificationReport = TriageClassificationEngine.Report
