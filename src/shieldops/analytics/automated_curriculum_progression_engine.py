"""Automated Curriculum Progression Engine — progressive difficulty curriculum scheduling for..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AutomatedCurriculumProgressionEngine = engine(
    "AutomatedCurriculumProgressionEngine",
    description="Progressive difficulty curriculum scheduling for SRE agent training.",
    enums={
        "stage": EnumDef(
            "CurriculumStage",
            {
                "FOUNDATION": "foundation",
                "INTERMEDIATE": "intermediate",
                "ADVANCED": "advanced",
                "MASTERY": "mastery",
            },
        ),
        "trigger": EnumDef(
            "ProgressionTrigger",
            {
                "SCORE_THRESHOLD": "score_threshold",
                "ITERATION_COUNT": "iteration_count",
                "PLATEAU_DETECTED": "plateau_detected",
                "PROPOSER_SIGNAL": "proposer_signal",
            },
        ),
        "adjustment": EnumDef(
            "DifficultyAdjustment",
            {
                "INCREASE": "increase",
                "MAINTAIN": "maintain",
                "DECREASE": "decrease",
                "RESET": "reset",
            },
        ),
    },
    record_fields=[
        FieldDef("current_difficulty", float, 0.0),
        FieldDef("iteration", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="solver_score",
    key_field="curriculum_id",
)

# Backward-compatible re-exports
CurriculumStage = AutomatedCurriculumProgressionEngine.CurriculumStage
ProgressionTrigger = AutomatedCurriculumProgressionEngine.ProgressionTrigger
DifficultyAdjustment = AutomatedCurriculumProgressionEngine.DifficultyAdjustment
CurriculumRecord = AutomatedCurriculumProgressionEngine.Record
CurriculumAnalysis = AutomatedCurriculumProgressionEngine.Analysis
CurriculumReport = AutomatedCurriculumProgressionEngine.Report
