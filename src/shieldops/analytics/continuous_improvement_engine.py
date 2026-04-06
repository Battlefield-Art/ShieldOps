"""ContinuousImprovementEngine — Track continuous improvement cycles across the agent fleet."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ContinuousImprovementEngine = engine(
    "ContinuousImprovementEngine",
    description="Track continuous improvement cycles across the agent fleet engine.",
    enums={
        "improvement_area": EnumDef(
            "ImprovementArea",
            {
                "ACCURACY": "accuracy",
                "SPEED": "speed",
                "COST": "cost",
                "COVERAGE": "coverage",
                "RELIABILITY": "reliability",
            },
        ),
        "cycle_phase": EnumDef(
            "CyclePhase",
            {
                "MEASURE": "measure",
                "ANALYZE": "analyze",
                "IMPROVE": "improve",
                "CONTROL": "control",
            },
        ),
        "improvement_status": EnumDef(
            "ImprovementStatus",
            {
                "IN_PROGRESS": "in_progress",
                "COMPLETED": "completed",
                "STALLED": "stalled",
                "REGRESSED": "regressed",
            },
        ),
    },
    record_fields=[
        FieldDef("baseline_value", float, 0.0),
        FieldDef("current_value", float, 0.0),
        FieldDef("target_value", float, 0.0),
    ],
)

# Backward-compatible re-exports
ImprovementArea = ContinuousImprovementEngine.ImprovementArea
CyclePhase = ContinuousImprovementEngine.CyclePhase
ImprovementStatus = ContinuousImprovementEngine.ImprovementStatus
ContinuousImprovementRecord = ContinuousImprovementEngine.Record
ContinuousImprovementAnalysis = ContinuousImprovementEngine.Analysis
ContinuousImprovementReport = ContinuousImprovementEngine.Report
