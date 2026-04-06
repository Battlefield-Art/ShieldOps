"""Exercise Readiness Analytics — measure team readiness from exercises."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExerciseReadinessAnalyticsEngine = engine(
    "ExerciseReadinessAnalyticsEngine",
    description="Measure team readiness from exercises.",
    enums={
        "metric": EnumDef(
            "ReadinessMetric",
            {
                "DETECTION_TIME": "detection_time",
                "RESPONSE_TIME": "response_time",
                "COORDINATION": "coordination",
                "COMMUNICATION": "communication",
                "RECOVERY": "recovery",
            },
        ),
        "performance": EnumDef(
            "TeamPerformance",
            {
                "EXCEPTIONAL": "exceptional",
                "PROFICIENT": "proficient",
                "DEVELOPING": "developing",
                "NEEDS_IMPROVEMENT": "needs_improvement",
                "UNTESTED": "untested",
            },
        ),
        "improvement": EnumDef(
            "ImprovementRate",
            {
                "RAPID": "rapid",
                "STEADY": "steady",
                "FLAT": "flat",
                "DECLINING": "declining",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("target_score", float, 0.0),
        FieldDef("team_name", str, ""),
    ],
    key_field="exercise_id",
)

# Backward-compatible re-exports
ReadinessMetric = ExerciseReadinessAnalyticsEngine.ReadinessMetric
TeamPerformance = ExerciseReadinessAnalyticsEngine.TeamPerformance
ImprovementRate = ExerciseReadinessAnalyticsEngine.ImprovementRate
ReadinessRecord = ExerciseReadinessAnalyticsEngine.Record
ReadinessAnalysis = ExerciseReadinessAnalyticsEngine.Analysis
ReadinessReport = ExerciseReadinessAnalyticsEngine.Report
