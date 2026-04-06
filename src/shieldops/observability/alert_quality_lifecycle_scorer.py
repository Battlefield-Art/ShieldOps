"""Alert Quality Lifecycle Scorer score alert actionability, identify low value alerts, track..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertQualityLifecycleScorer = engine(
    "AlertQualityLifecycleScorer",
    description="Score alert actionability, identify low value alerts, track alert quality t...",
    enums={
        "quality_grade": EnumDef(
            "QualityGrade",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
        "alert_phase": EnumDef(
            "AlertPhase",
            {
                "CREATION": "creation",
                "ACTIVE": "active",
                "TUNING": "tuning",
                "RETIREMENT": "retirement",
            },
        ),
        "actionability": EnumDef(
            "ActionabilityLevel",
            {
                "IMMEDIATE": "immediate",
                "DEFERRED": "deferred",
                "INFORMATIONAL": "informational",
                "NOISE": "noise",
            },
        ),
    },
    record_fields=[
        FieldDef("action_taken", bool, False),
        FieldDef("resolution_time_min", float, 0.0),
        FieldDef("source", str, ""),
    ],
    score_field="quality_score",
    key_field="alert_name",
)

# Backward-compatible re-exports
QualityGrade = AlertQualityLifecycleScorer.QualityGrade
AlertPhase = AlertQualityLifecycleScorer.AlertPhase
ActionabilityLevel = AlertQualityLifecycleScorer.ActionabilityLevel
AlertQualityRecord = AlertQualityLifecycleScorer.Record
AlertQualityAnalysis = AlertQualityLifecycleScorer.Analysis
AlertQualityReport = AlertQualityLifecycleScorer.Report
