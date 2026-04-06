"""Agent Curriculum Learning Engine — design progressive learning curricula, evaluate progress..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentCurriculumLearningEngine = engine(
    "AgentCurriculumLearningEngine",
    description="Design progressive task difficulty for agent training, evaluate readiness,...",
    enums={
        "difficulty": EnumDef(
            "DifficultyLevel",
            {
                "BEGINNER": "beginner",
                "INTERMEDIATE": "intermediate",
                "ADVANCED": "advanced",
                "EXPERT": "expert",
            },
        ),
        "phase": EnumDef(
            "CurriculumPhase",
            {
                "WARMUP": "warmup",
                "TRAINING": "training",
                "EVALUATION": "evaluation",
                "MASTERY": "mastery",
            },
        ),
        "progress": EnumDef(
            "LearningProgress",
            {
                "BEHIND": "behind",
                "ON_TRACK": "on_track",
                "AHEAD": "ahead",
                "COMPLETED": "completed",
            },
        ),
    },
    record_fields=[
        FieldDef("completion_rate", float, 0.0),
        FieldDef("episodes_completed", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="task_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
DifficultyLevel = AgentCurriculumLearningEngine.DifficultyLevel
CurriculumPhase = AgentCurriculumLearningEngine.CurriculumPhase
LearningProgress = AgentCurriculumLearningEngine.LearningProgress
CurriculumLearningRecord = AgentCurriculumLearningEngine.Record
CurriculumLearningAnalysis = AgentCurriculumLearningEngine.Analysis
CurriculumLearningReport = AgentCurriculumLearningEngine.Report
