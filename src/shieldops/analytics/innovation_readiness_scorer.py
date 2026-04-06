"""InnovationReadinessScorer — innovation readiness scorer."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

InnovationReadinessScorer = engine(
    "InnovationReadinessScorer",
    module="operations",  # uses record_item
    description="Innovation Readiness Scorer.",
    enums={
        "readiness_dimension": EnumDef(
            "ReadinessDimension",
            {
                "TECHNOLOGY": "technology",
                "PROCESS": "process",
                "PEOPLE": "people",
                "CULTURE": "culture",
                "GOVERNANCE": "governance",
            },
        ),
        "readiness_level": EnumDef(
            "ReadinessLevel",
            {
                "PIONEER": "pioneer",
                "EARLY_ADOPTER": "early_adopter",
                "MAINSTREAM": "mainstream",
                "LATE_ADOPTER": "late_adopter",
                "LAGGARD": "laggard",
            },
        ),
        "innovation_barrier": EnumDef(
            "InnovationBarrier",
            {
                "TECHNICAL": "technical",
                "ORGANIZATIONAL": "organizational",
                "FINANCIAL": "financial",
                "CULTURAL": "cultural",
                "REGULATORY": "regulatory",
            },
        ),
    },
)

# Backward-compatible re-exports
ReadinessDimension = InnovationReadinessScorer.ReadinessDimension
ReadinessLevel = InnovationReadinessScorer.ReadinessLevel
InnovationBarrier = InnovationReadinessScorer.InnovationBarrier
InnovationReadinessScorerRecord = InnovationReadinessScorer.Record
InnovationReadinessScorerAnalysis = InnovationReadinessScorer.Analysis
InnovationReadinessScorerReport = InnovationReadinessScorer.Report
