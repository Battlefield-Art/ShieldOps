"""Regulatory Change Velocity Tracker compute change velocity by jurisdiction, detect high-imp..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RegulatoryChangeVelocityTracker = engine(
    "RegulatoryChangeVelocityTracker",
    description="Compute change velocity by jurisdiction, detect high-impact changes, rank r...",
    enums={
        "change_impact": EnumDef(
            "ChangeImpact",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "jurisdiction": EnumDef(
            "Jurisdiction",
            {
                "US_FEDERAL": "us_federal",
                "EU": "eu",
                "UK": "uk",
                "APAC": "apac",
            },
        ),
        "change_type": EnumDef(
            "ChangeType",
            {
                "NEW_REQUIREMENT": "new_requirement",
                "AMENDMENT": "amendment",
                "REPEAL": "repeal",
                "GUIDANCE": "guidance",
            },
        ),
    },
    record_fields=[
        FieldDef("affected_controls", int, 0),
        FieldDef("regulation_name", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="velocity_score",
    key_field="regulation_id",
)

# Backward-compatible re-exports
ChangeImpact = RegulatoryChangeVelocityTracker.ChangeImpact
Jurisdiction = RegulatoryChangeVelocityTracker.Jurisdiction
ChangeType = RegulatoryChangeVelocityTracker.ChangeType
RegulatoryChangeRecord = RegulatoryChangeVelocityTracker.Record
RegulatoryChangeAnalysis = RegulatoryChangeVelocityTracker.Analysis
RegulatoryChangeReport = RegulatoryChangeVelocityTracker.Report
