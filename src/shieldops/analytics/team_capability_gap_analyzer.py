"""Team Capability Gap Analyzer — identify capability gaps, compute gap criticality, rank gaps..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TeamCapabilityGapAnalyzer = engine(
    "TeamCapabilityGapAnalyzer",
    description="Identify capability gaps, compute criticality, rank gaps by business impact.",
    enums={
        "domain": EnumDef(
            "CapabilityDomain",
            {
                "FRONTEND": "frontend",
                "BACKEND": "backend",
                "INFRASTRUCTURE": "infrastructure",
                "SECURITY": "security",
            },
        ),
        "severity": EnumDef(
            "GapSeverity",
            {
                "CRITICAL": "critical",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "MINOR": "minor",
            },
        ),
        "remediation": EnumDef(
            "RemediationPath",
            {
                "HIRING": "hiring",
                "TRAINING": "training",
                "TOOLING": "tooling",
                "OUTSOURCING": "outsourcing",
            },
        ),
    },
    record_fields=[
        FieldDef("team_id", str, ""),
        FieldDef("current_level", float, 0.0),
        FieldDef("required_level", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="impact_score",
    key_field="gap_id",
)

# Backward-compatible re-exports
CapabilityDomain = TeamCapabilityGapAnalyzer.CapabilityDomain
GapSeverity = TeamCapabilityGapAnalyzer.GapSeverity
RemediationPath = TeamCapabilityGapAnalyzer.RemediationPath
CapabilityGapRecord = TeamCapabilityGapAnalyzer.Record
CapabilityGapAnalysis = TeamCapabilityGapAnalyzer.Analysis
CapabilityGapReport = TeamCapabilityGapAnalyzer.Report
