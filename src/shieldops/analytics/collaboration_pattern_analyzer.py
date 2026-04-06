"""Collaboration Pattern Analyzer — analyze collaboration density, detect gaps, rank teams by..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CollaborationPatternAnalyzer = engine(
    "CollaborationPatternAnalyzer",
    description="Analyze collaboration density, detect gaps, rank teams by cross-team engage...",
    enums={
        "collab_type": EnumDef(
            "CollaborationType",
            {
                "CODE_REVIEW": "code_review",
                "PAIRING": "pairing",
                "INCIDENT_RESPONSE": "incident_response",
                "PLANNING": "planning",
            },
        ),
        "health": EnumDef(
            "PatternHealth",
            {
                "THRIVING": "thriving",
                "ADEQUATE": "adequate",
                "FRAGMENTED": "fragmented",
                "SILOED": "siloed",
            },
        ),
        "engagement": EnumDef(
            "EngagementLevel",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("partner_team_id", str, ""),
        FieldDef("interaction_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="quality_score",
    key_field="team_id",
)

# Backward-compatible re-exports
CollaborationType = CollaborationPatternAnalyzer.CollaborationType
PatternHealth = CollaborationPatternAnalyzer.PatternHealth
EngagementLevel = CollaborationPatternAnalyzer.EngagementLevel
CollaborationRecord = CollaborationPatternAnalyzer.Record
CollaborationAnalysis = CollaborationPatternAnalyzer.Analysis
CollaborationReport = CollaborationPatternAnalyzer.Report
