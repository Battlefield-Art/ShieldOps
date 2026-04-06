"""Developer Experience Intelligence — compute devex score, detect friction points, rank tools..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DeveloperExperienceIntelligence = engine(
    "DeveloperExperienceIntelligence",
    description="Compute devex score, detect friction points, rank tools by developer satisf...",
    enums={
        "dimension": EnumDef(
            "DevexDimension",
            {
                "TOOLING": "tooling",
                "DOCUMENTATION": "documentation",
                "ONBOARDING": "onboarding",
                "WORKFLOW": "workflow",
            },
        ),
        "friction": EnumDef(
            "FrictionType",
            {
                "SETUP": "setup",
                "BUILD": "build",
                "TEST": "test",
                "DEPLOY": "deploy",
            },
        ),
        "satisfaction": EnumDef(
            "SatisfactionLevel",
            {
                "DELIGHTED": "delighted",
                "SATISFIED": "satisfied",
                "NEUTRAL": "neutral",
                "FRUSTRATED": "frustrated",
            },
        ),
    },
    record_fields=[
        FieldDef("developer_id", str, ""),
        FieldDef("time_lost_minutes", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="tool_id",
)

# Backward-compatible re-exports
DevexDimension = DeveloperExperienceIntelligence.DevexDimension
FrictionType = DeveloperExperienceIntelligence.FrictionType
SatisfactionLevel = DeveloperExperienceIntelligence.SatisfactionLevel
DevexRecord = DeveloperExperienceIntelligence.Record
DevexAnalysis = DeveloperExperienceIntelligence.Analysis
DevexReport = DeveloperExperienceIntelligence.Report
