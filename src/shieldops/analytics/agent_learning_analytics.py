"""Agent Learning Analytics — measure agent learning."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentLearningAnalyticsEngine = engine(
    "AgentLearningAnalyticsEngine",
    description="Measure and track agent learning progress.",
    enums={
        "metric": EnumDef(
            "LearningMetric",
            {
                "ACCURACY_IMPROVEMENT": "accuracy_improvement",
                "FP_REDUCTION": "fp_reduction",
                "SPEED_GAIN": "speed_gain",
                "COVERAGE_EXPANSION": "coverage_expansion",
            },
        ),
        "area": EnumDef(
            "KnowledgeArea",
            {
                "DETECTION": "detection",
                "TRIAGE": "triage",
                "RESPONSE": "response",
                "INVESTIGATION": "investigation",
            },
        ),
        "retention": EnumDef(
            "RetentionRate",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "DECAYED": "decayed",
            },
        ),
    },
    record_fields=[
        FieldDef("baseline_value", float, 0.0),
        FieldDef("current_value", float, 0.0),
        FieldDef("improvement_pct", float, 0.0),
        FieldDef("sample_count", int, 0),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
LearningMetric = AgentLearningAnalyticsEngine.LearningMetric
KnowledgeArea = AgentLearningAnalyticsEngine.KnowledgeArea
RetentionRate = AgentLearningAnalyticsEngine.RetentionRate
LearningRecord = AgentLearningAnalyticsEngine.Record
LearningAnalysis = AgentLearningAnalyticsEngine.Analysis
LearningReport = AgentLearningAnalyticsEngine.Report
