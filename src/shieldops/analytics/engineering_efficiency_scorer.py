"""Engineering Efficiency Scorer — compute efficiency index, detect drains, rank workflows by..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EngineeringEfficiencyScorer = engine(
    "EngineeringEfficiencyScorer",
    description="Compute efficiency index, detect drains, rank workflows by optimization pot...",
    enums={
        "dimension": EnumDef(
            "EfficiencyDimension",
            {
                "BUILD_TIME": "build_time",
                "REVIEW_CYCLE": "review_cycle",
                "DEPLOY_FREQUENCY": "deploy_frequency",
                "INCIDENT_RESPONSE": "incident_response",
            },
        ),
        "drain_type": EnumDef(
            "DrainType",
            {
                "TOOLING": "tooling",
                "PROCESS": "process",
                "COMMUNICATION": "communication",
                "CONTEXT_SWITCHING": "context_switching",
            },
        ),
        "grade": EnumDef(
            "EfficiencyGrade",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
    },
    record_fields=[
        FieldDef("team_id", str, ""),
        FieldDef("time_spent_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="efficiency_score",
    key_field="workflow_id",
)

# Backward-compatible re-exports
EfficiencyDimension = EngineeringEfficiencyScorer.EfficiencyDimension
DrainType = EngineeringEfficiencyScorer.DrainType
EfficiencyGrade = EngineeringEfficiencyScorer.EfficiencyGrade
EfficiencyRecord = EngineeringEfficiencyScorer.Record
EfficiencyAnalysis = EngineeringEfficiencyScorer.Analysis
EfficiencyReport = EngineeringEfficiencyScorer.Report
