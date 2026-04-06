"""Autonomous Ops Maturity Scorer — autonomous operations maturity scoring and roadmap."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousOpsMaturityScorer = engine(
    "AutonomousOpsMaturityScorer",
    description="Autonomous Ops Maturity Scorer — autonomous operations maturity scoring and...",
    enums={
        "maturity_pillar": EnumDef(
            "MaturityPillar",
            {
                "AUTOMATION": "automation",
                "OBSERVABILITY": "observability",
                "INCIDENT_MANAGEMENT": "incident_management",
                "CAPACITY": "capacity",
                "SECURITY": "security",
            },
        ),
        "assessment_source": EnumDef(
            "AssessmentSource",
            {
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "BENCHMARK": "benchmark",
                "SURVEY": "survey",
                "INTEGRATION_CHECK": "integration_check",
            },
        ),
        "maturity_tier": EnumDef(
            "MaturityTier",
            {
                "AUTONOMOUS": "autonomous",
                "PROACTIVE": "proactive",
                "REACTIVE": "reactive",
                "MANUAL": "manual",
                "AD_HOC": "ad_hoc",
            },
        ),
    },
)

# Backward-compatible re-exports
MaturityPillar = AutonomousOpsMaturityScorer.MaturityPillar
AssessmentSource = AutonomousOpsMaturityScorer.AssessmentSource
MaturityTier = AutonomousOpsMaturityScorer.MaturityTier
MaturityPillarRecord = AutonomousOpsMaturityScorer.Record
MaturityPillarAnalysis = AutonomousOpsMaturityScorer.Analysis
AutonomousOpsMaturityReport = AutonomousOpsMaturityScorer.Report
