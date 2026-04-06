"""Organizational Resilience Scorer — compute resilience score, detect gaps, rank capabilities..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OrganizationalResilienceScorer = engine(
    "OrganizationalResilienceScorer",
    description="Compute resilience score, detect gaps, rank capabilities by improvement pri...",
    enums={
        "dimension": EnumDef(
            "ResilienceDimension",
            {
                "TECHNICAL": "technical",
                "PROCESS": "process",
                "PEOPLE": "people",
                "CULTURE": "culture",
            },
        ),
        "gap_type": EnumDef(
            "GapType",
            {
                "SINGLE_POINT_OF_FAILURE": "single_point_of_failure",
                "KNOWLEDGE_GAP": "knowledge_gap",
                "PROCESS_GAP": "process_gap",
                "TOOLING_GAP": "tooling_gap",
            },
        ),
        "maturity": EnumDef(
            "MaturityLevel",
            {
                "OPTIMIZED": "optimized",
                "MANAGED": "managed",
                "DEFINED": "defined",
                "INITIAL": "initial",
            },
        ),
    },
    record_fields=[
        FieldDef("team_id", str, ""),
        FieldDef("recovery_time_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="resilience_score",
    key_field="capability_id",
)

# Backward-compatible re-exports
ResilienceDimension = OrganizationalResilienceScorer.ResilienceDimension
GapType = OrganizationalResilienceScorer.GapType
MaturityLevel = OrganizationalResilienceScorer.MaturityLevel
ResilienceRecord = OrganizationalResilienceScorer.Record
ResilienceAnalysis = OrganizationalResilienceScorer.Analysis
ResilienceReport = OrganizationalResilienceScorer.Report
