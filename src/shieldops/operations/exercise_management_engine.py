"""Exercise Management Engine — manage incident exercises and scoring."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExerciseManagementEngine = engine(
    "ExerciseManagementEngine",
    module="operations",  # uses record_item
    description="Manage incident exercises and scoring.",
    enums={
        "phase": EnumDef(
            "ExercisePhase",
            {
                "PLANNING": "planning",
                "BRIEFING": "briefing",
                "EXECUTION": "execution",
                "HOT_WASH": "hot_wash",
                "AFTER_ACTION": "after_action",
            },
        ),
        "inject_type": EnumDef(
            "InjectType",
            {
                "SCENARIO_UPDATE": "scenario_update",
                "COMPLICATION": "complication",
                "RESOURCE_CHANGE": "resource_change",
                "EXTERNAL_EVENT": "external_event",
                "TIME_PRESSURE": "time_pressure",
            },
        ),
        "score_category": EnumDef(
            "ScoreCategory",
            {
                "DETECTION": "detection",
                "RESPONSE": "response",
                "COMMUNICATION": "communication",
                "DECISION_MAKING": "decision_making",
                "RECOVERY": "recovery",
            },
        ),
    },
    record_fields=[
        FieldDef("team_name", str, ""),
        FieldDef("participants", int, 0),
    ],
    key_field="exercise_name",
)

# Backward-compatible re-exports
ExercisePhase = ExerciseManagementEngine.ExercisePhase
InjectType = ExerciseManagementEngine.InjectType
ScoreCategory = ExerciseManagementEngine.ScoreCategory
ExerciseRecord = ExerciseManagementEngine.Record
ExerciseAnalysis = ExerciseManagementEngine.Analysis
ExerciseReport = ExerciseManagementEngine.Report
