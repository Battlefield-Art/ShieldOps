"""OperationalExcellenceScorer — operational excellence scorer."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OperationalExcellenceScorer = engine(
    "OperationalExcellenceScorer",
    module="operations",  # uses record_item
    description="Operational Excellence Scorer.",
    enums={
        "excellence_pillar": EnumDef(
            "ExcellencePillar",
            {
                "RELIABILITY": "reliability",
                "PERFORMANCE": "performance",
                "SECURITY": "security",
                "COST": "cost",
                "OPERATIONAL": "operational",
            },
        ),
        "pillar_score": EnumDef(
            "PillarScore",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
        "improvement_priority": EnumDef(
            "ImprovementPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "OPTIONAL": "optional",
            },
        ),
    },
)

# Backward-compatible re-exports
ExcellencePillar = OperationalExcellenceScorer.ExcellencePillar
PillarScore = OperationalExcellenceScorer.PillarScore
ImprovementPriority = OperationalExcellenceScorer.ImprovementPriority
OperationalExcellenceScorerRecord = OperationalExcellenceScorer.Record
OperationalExcellenceScorerAnalysis = OperationalExcellenceScorer.Analysis
OperationalExcellenceScorerReport = OperationalExcellenceScorer.Report
