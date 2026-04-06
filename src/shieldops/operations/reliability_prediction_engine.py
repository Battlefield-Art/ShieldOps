"""ReliabilityPredictionEngine — reliability prediction engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ReliabilityPredictionEngine = engine(
    "ReliabilityPredictionEngine",
    module="operations",  # uses record_item
    description="Reliability Prediction Engine.",
    enums={
        "reliability_metric": EnumDef(
            "ReliabilityMetric",
            {
                "MTBF": "mtbf",
                "MTTR": "mttr",
                "MTTD": "mttd",
                "AVAILABILITY": "availability",
                "DURABILITY": "durability",
            },
        ),
        "prediction_basis": EnumDef(
            "PredictionBasis",
            {
                "HISTORICAL": "historical",
                "MODEL_BASED": "model_based",
                "EXPERT_JUDGMENT": "expert_judgment",
                "SIMULATION": "simulation",
                "HYBRID": "hybrid",
            },
        ),
        "reliability_trend": EnumDef(
            "ReliabilityTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
ReliabilityMetric = ReliabilityPredictionEngine.ReliabilityMetric
PredictionBasis = ReliabilityPredictionEngine.PredictionBasis
ReliabilityTrend = ReliabilityPredictionEngine.ReliabilityTrend
ReliabilityPredictionEngineRecord = ReliabilityPredictionEngine.Record
ReliabilityPredictionEngineAnalysis = ReliabilityPredictionEngine.Analysis
ReliabilityPredictionEngineReport = ReliabilityPredictionEngine.Report
