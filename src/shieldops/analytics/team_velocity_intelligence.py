"""Team Velocity Intelligence Engine — track team velocity, detect anomalies, rank teams by de..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TeamVelocityIntelligence = engine(
    "TeamVelocityIntelligence",
    description="Track team velocity, detect anomalies, rank teams by delivery consistency.",
    enums={
        "metric": EnumDef(
            "VelocityMetric",
            {
                "STORY_POINTS": "story_points",
                "TASKS_COMPLETED": "tasks_completed",
                "DEPLOYMENTS": "deployments",
                "INCIDENTS_RESOLVED": "incidents_resolved",
            },
        ),
        "trend": EnumDef(
            "TrendDirection",
            {
                "ACCELERATING": "accelerating",
                "STABLE": "stable",
                "DECELERATING": "decelerating",
                "VOLATILE": "volatile",
            },
        ),
        "team_size": EnumDef(
            "TeamSize",
            {
                "SMALL": "small",
                "MEDIUM": "medium",
                "LARGE": "large",
                "DISTRIBUTED": "distributed",
            },
        ),
    },
    record_fields=[
        FieldDef("velocity_value", float, 0.0),
        FieldDef("sprint_number", int, 0),
        FieldDef("capacity", float, 1.0),
        FieldDef("description", str, ""),
    ],
    key_field="team_id",
)

# Backward-compatible re-exports
VelocityMetric = TeamVelocityIntelligence.VelocityMetric
TrendDirection = TeamVelocityIntelligence.TrendDirection
TeamSize = TeamVelocityIntelligence.TeamSize
TeamVelocityRecord = TeamVelocityIntelligence.Record
TeamVelocityAnalysis = TeamVelocityIntelligence.Analysis
TeamVelocityReport = TeamVelocityIntelligence.Report
