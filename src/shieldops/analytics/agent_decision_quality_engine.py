"""AgentDecisionQualityEngine — Evaluate the quality of agent decisions over time."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentDecisionQualityEngine = engine(
    "AgentDecisionQualityEngine",
    description="Evaluate the quality of agent decisions over time.",
    enums={
        "decision_type": EnumDef(
            "DecisionType",
            {
                "INVESTIGATE": "investigate",
                "REMEDIATE": "remediate",
                "ESCALATE": "escalate",
                "IGNORE": "ignore",
            },
        ),
        "decision_outcome": EnumDef(
            "DecisionOutcome",
            {
                "CORRECT": "correct",
                "INCORRECT": "incorrect",
                "PARTIAL": "partial",
                "OVERRIDDEN": "overridden",
            },
        ),
        "quality_trend": EnumDef(
            "QualityTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DECLINING": "declining",
            },
        ),
    },
    record_fields=[
        FieldDef("confidence", float, 0.0),
        FieldDef("response_time_sec", float, 0.0),
    ],
)

# Backward-compatible re-exports
DecisionType = AgentDecisionQualityEngine.DecisionType
DecisionOutcome = AgentDecisionQualityEngine.DecisionOutcome
QualityTrend = AgentDecisionQualityEngine.QualityTrend
AgentDecisionQualityRecord = AgentDecisionQualityEngine.Record
AgentDecisionQualityAnalysis = AgentDecisionQualityEngine.Analysis
AgentDecisionQualityReport = AgentDecisionQualityEngine.Report
