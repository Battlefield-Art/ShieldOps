"""AgentCurriculumEngine — progressive learning curriculum for agents."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentCurriculumEngine = engine(
    "AgentCurriculumEngine",
    description="Progressive learning curriculum for agents — determines what to learn next.",
    enums={
        "difficulty_level": EnumDef(
            "DifficultyLevel",
            {
                "BEGINNER": "beginner",
                "INTERMEDIATE": "intermediate",
                "ADVANCED": "advanced",
                "EXPERT": "expert",
            },
        ),
        "learning_objective": EnumDef(
            "LearningObjective",
            {
                "ACCURACY": "accuracy",
                "SPEED": "speed",
                "COST_EFFICIENCY": "cost_efficiency",
                "COVERAGE": "coverage",
            },
        ),
        "curriculum_status": EnumDef(
            "CurriculumStatus",
            {
                "NOT_STARTED": "not_started",
                "IN_PROGRESS": "in_progress",
                "MASTERED": "mastered",
                "REGRESSED": "regressed",
            },
        ),
    },
    record_fields=[
        FieldDef("mastery_pct", float, 0.0),
        FieldDef("agent_id", str, ""),
    ],
)

# Backward-compatible re-exports
DifficultyLevel = AgentCurriculumEngine.DifficultyLevel
LearningObjective = AgentCurriculumEngine.LearningObjective
CurriculumStatus = AgentCurriculumEngine.CurriculumStatus
AgentCurriculumRecord = AgentCurriculumEngine.Record
AgentCurriculumAnalysis = AgentCurriculumEngine.Analysis
AgentCurriculumReport = AgentCurriculumEngine.Report
