"""Sprint Health Intelligence — compute sprint health score, detect antipatterns, rank sprints..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SprintHealthIntelligence = engine(
    "SprintHealthIntelligence",
    description="Compute sprint health score, detect antipatterns, rank sprints by predictab...",
    enums={
        "outcome": EnumDef(
            "SprintOutcome",
            {
                "COMPLETED": "completed",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "CANCELLED": "cancelled",
            },
        ),
        "antipattern": EnumDef(
            "AntipatternType",
            {
                "SCOPE_CREEP": "scope_creep",
                "CARRYOVER": "carryover",
                "FRONT_LOADING": "front_loading",
                "BACK_LOADING": "back_loading",
            },
        ),
        "indicator": EnumDef(
            "HealthIndicator",
            {
                "VELOCITY": "velocity",
                "SCOPE_STABILITY": "scope_stability",
                "COMPLETION_RATE": "completion_rate",
                "QUALITY": "quality",
            },
        ),
    },
    record_fields=[
        FieldDef("team_id", str, ""),
        FieldDef("completion_pct", float, 0.0),
        FieldDef("scope_change_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="health_score",
    key_field="sprint_id",
)

# Backward-compatible re-exports
SprintOutcome = SprintHealthIntelligence.SprintOutcome
AntipatternType = SprintHealthIntelligence.AntipatternType
HealthIndicator = SprintHealthIntelligence.HealthIndicator
SprintHealthRecord = SprintHealthIntelligence.Record
SprintHealthAnalysis = SprintHealthIntelligence.Analysis
SprintHealthReport = SprintHealthIntelligence.Report
