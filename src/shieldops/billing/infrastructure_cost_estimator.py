"""Infrastructure Cost Estimator estimate plan cost impact, detect cost surprises, rank change..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InfrastructureCostEstimator = engine(
    "InfrastructureCostEstimator",
    description="Estimate plan cost impact, detect cost surprises, rank changes by cost delta.",
    enums={
        "cost_impact": EnumDef(
            "CostImpact",
            {
                "INCREASE": "increase",
                "DECREASE": "decrease",
                "NEUTRAL": "neutral",
                "UNKNOWN": "unknown",
            },
        ),
        "estimation_confidence": EnumDef(
            "EstimationConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
            },
        ),
        "pricing_model": EnumDef(
            "PricingModel",
            {
                "ON_DEMAND": "on_demand",
                "RESERVED": "reserved",
                "SPOT": "spot",
                "COMMITTED": "committed",
            },
        ),
    },
    record_fields=[
        FieldDef("resource_name", str, ""),
        FieldDef("estimated_monthly_cost", float, 0.0),
        FieldDef("cost_delta", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="change_id",
)

# Backward-compatible re-exports
CostImpact = InfrastructureCostEstimator.CostImpact
EstimationConfidence = InfrastructureCostEstimator.EstimationConfidence
PricingModel = InfrastructureCostEstimator.PricingModel
CostEstimationRecord = InfrastructureCostEstimator.Record
CostEstimationAnalysis = InfrastructureCostEstimator.Analysis
CostEstimationReport = InfrastructureCostEstimator.Report
