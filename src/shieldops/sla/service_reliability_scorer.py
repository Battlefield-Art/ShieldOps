"""Service Reliability Scorer compute composite reliability scores, detect reliability degrada..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceReliabilityScorer = engine(
    "ServiceReliabilityScorer",
    description="Compute composite reliability scores, detect reliability degradation, rank...",
    enums={
        "reliability_tier": EnumDef(
            "ReliabilityTier",
            {
                "PLATINUM": "platinum",
                "GOLD": "gold",
                "SILVER": "silver",
                "BRONZE": "bronze",
            },
        ),
        "metric_type": EnumDef(
            "MetricType",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "ERROR_RATE": "error_rate",
                "THROUGHPUT": "throughput",
            },
        ),
        "scoring_model": EnumDef(
            "ScoringModel",
            {
                "WEIGHTED": "weighted",
                "EQUAL": "equal",
                "ADAPTIVE": "adaptive",
                "CUSTOM": "custom",
            },
        ),
    },
    record_fields=[
        FieldDef("threshold", float, 99.0),
        FieldDef("region", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
ReliabilityTier = ServiceReliabilityScorer.ReliabilityTier
MetricType = ServiceReliabilityScorer.MetricType
ScoringModel = ServiceReliabilityScorer.ScoringModel
ServiceReliabilityRecord = ServiceReliabilityScorer.Record
ServiceReliabilityAnalysis = ServiceReliabilityScorer.Analysis
ServiceReliabilityReport = ServiceReliabilityScorer.Report
