"""Release Impact Intelligence release impact intelligence with pre and post-deployment analysis."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ReleaseImpactIntelligence = engine(
    "ReleaseImpactIntelligence",
    description="Release Impact Intelligence release impact intelligence with pre and post-d...",
    enums={
        "impact_area": EnumDef(
            "ImpactArea",
            {
                "PERFORMANCE": "performance",
                "RELIABILITY": "reliability",
                "SECURITY": "security",
                "USER_EXPERIENCE": "user_experience",
                "COST": "cost",
            },
        ),
        "analysis_phase": EnumDef(
            "AnalysisPhase",
            {
                "PRE_RELEASE": "pre_release",
                "CANARY": "canary",
                "ROLLOUT": "rollout",
                "POST_RELEASE": "post_release",
                "RETROSPECTIVE": "retrospective",
            },
        ),
        "impact_severity": EnumDef(
            "ImpactSeverity",
            {
                "CRITICAL": "critical",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "MINOR": "minor",
                "POSITIVE": "positive",
            },
        ),
    },
)

# Backward-compatible re-exports
ImpactArea = ReleaseImpactIntelligence.ImpactArea
AnalysisPhase = ReleaseImpactIntelligence.AnalysisPhase
ImpactSeverity = ReleaseImpactIntelligence.ImpactSeverity
ReleaseImpactRecord = ReleaseImpactIntelligence.Record
ReleaseImpactAnalysis = ReleaseImpactIntelligence.Analysis
ReleaseImpactReport = ReleaseImpactIntelligence.Report
