"""APT Exercise Analytics — measure defense effectiveness."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

APTExerciseAnalytics = engine(
    "APTExerciseAnalytics",
    description="Measure APT exercise and defense effectiveness.",
    enums={
        "metric": EnumDef(
            "ExerciseMetric",
            {
                "DETECTION_RATE": "detection_rate",
                "RESPONSE_TIME": "response_time",
                "CONTAINMENT_SPEED": "containment_speed",
                "FALSE_POSITIVE_RATE": "false_positive_rate",
                "COVERAGE": "coverage",
            },
        ),
        "effectiveness": EnumDef(
            "DefenseEffectiveness",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ADEQUATE": "adequate",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
        "attack_result": EnumDef(
            "AttackSuccess",
            {
                "BLOCKED": "blocked",
                "DETECTED": "detected",
                "PARTIALLY_DETECTED": "partially_detected",
                "EVADED": "evaded",
                "UNKNOWN": "unknown",
            },
        ),
    },
    key_field="exercise_name",
)

# Backward-compatible re-exports
ExerciseMetric = APTExerciseAnalytics.ExerciseMetric
DefenseEffectiveness = APTExerciseAnalytics.DefenseEffectiveness
AttackSuccess = APTExerciseAnalytics.AttackSuccess
ExerciseRecord = APTExerciseAnalytics.Record
ExerciseAnalysis = APTExerciseAnalytics.Analysis
ExerciseReport = APTExerciseAnalytics.Report
