"""Agent Reflection Tracker — track agent self-reflection."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentReflectionTrackerEngine = engine(
    "AgentReflectionTrackerEngine",
    description="Track agent self-reflection and learning.",
    enums={
        "depth": EnumDef(
            "ReflectionDepth",
            {
                "DEEP": "deep",
                "STANDARD": "standard",
                "SHALLOW": "shallow",
            },
        ),
        "outcome": EnumDef(
            "ActionOutcome",
            {
                "EFFECTIVE": "effective",
                "PARTIAL": "partial",
                "INEFFECTIVE": "ineffective",
                "COUNTERPRODUCTIVE": "counterproductive",
            },
        ),
        "category": EnumDef(
            "LearningCategory",
            {
                "THRESHOLD_TUNE": "threshold_tune",
                "RULE_UPDATE": "rule_update",
                "PLAYBOOK_FIX": "playbook_fix",
                "FP_SUPPRESS": "fp_suppress",
            },
        ),
    },
    record_fields=[
        FieldDef("action_taken", str, ""),
        FieldDef("lesson_learned", str, ""),
        FieldDef("confidence", float, 0.0),
        FieldDef("mistake_repeated", bool, False),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
ReflectionDepth = AgentReflectionTrackerEngine.ReflectionDepth
ActionOutcome = AgentReflectionTrackerEngine.ActionOutcome
LearningCategory = AgentReflectionTrackerEngine.LearningCategory
ReflectionRecord = AgentReflectionTrackerEngine.Record
ReflectionAnalysis = AgentReflectionTrackerEngine.Analysis
ReflectionReport = AgentReflectionTrackerEngine.Report
