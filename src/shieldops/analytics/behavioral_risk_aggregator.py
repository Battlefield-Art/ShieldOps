"""Behavioral Risk Aggregator — aggregate risk signals from multiple sources.

Generated via ``shieldops.engine.engine()`` factory.
"""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

# --- Build the engine class from a declarative spec ---

BehavioralRiskAggregator = engine(
    "BehavioralRiskAggregator",
    module="analytics",
    description="Aggregate risk signals from multiple sources using various aggregation methods.",
    enums={
        "risk_source": EnumDef(
            name="RiskSource",
            values={
                "UEBA": "ueba",
                "DLP": "dlp",
                "IAM": "iam",
                "NETWORK": "network",
                "ENDPOINT": "endpoint",
            },
        ),
        "aggregation_method": EnumDef(
            name="AggregationMethod",
            values={
                "WEIGHTED_AVERAGE": "weighted_average",
                "MAXIMUM": "maximum",
                "BAYESIAN": "bayesian",
                "ENSEMBLE": "ensemble",
                "CUSTOM": "custom",
            },
        ),
        "risk_tier": EnumDef(
            name="RiskTier",
            values={
                "NORMAL": "normal",
                "CRITICAL": "critical",
                "HIGH": "high",
                "ELEVATED": "elevated",
                "LOW": "low",
            },
        ),
    },
    score_field="aggregated_score",
    key_field="entity_name",
    group_field="service",
    threshold=50.0,
    max_records=200_000,
)

# --- Add legacy alias: record_risk -> add_record ---

BehavioralRiskAggregator.record_risk = BehavioralRiskAggregator.add_record  # type: ignore[attr-defined]

# --- Re-export enum and model classes for backward compatibility ---

RiskSource = BehavioralRiskAggregator.RiskSource  # type: ignore[attr-defined]
AggregationMethod = BehavioralRiskAggregator.AggregationMethod  # type: ignore[attr-defined]
RiskTier = BehavioralRiskAggregator.RiskTier  # type: ignore[attr-defined]

AggregatedRiskRecord = BehavioralRiskAggregator.Record  # type: ignore[attr-defined]
AggregatedRiskAnalysis = BehavioralRiskAggregator.Analysis  # type: ignore[attr-defined]
BehavioralRiskReport = BehavioralRiskAggregator.Report  # type: ignore[attr-defined]
