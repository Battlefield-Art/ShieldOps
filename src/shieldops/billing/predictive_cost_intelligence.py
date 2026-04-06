"""PredictiveCostIntelligence — predictive cost intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveCostIntelligence = engine(
    "PredictiveCostIntelligence",
    module="operations",  # uses record_item
    description="Predictive Cost Intelligence.",
    enums={
        "cost_driver": EnumDef(
            "CostDriver",
            {
                "COMPUTE": "compute",
                "STORAGE": "storage",
                "NETWORK": "network",
                "LICENSE": "license",
                "SUPPORT": "support",
            },
        ),
        "cost_forecast": EnumDef(
            "CostForecast",
            {
                "UNDER_BUDGET": "under_budget",
                "ON_BUDGET": "on_budget",
                "OVER_BUDGET": "over_budget",
                "SIGNIFICANTLY_OVER": "significantly_over",
                "UNKNOWN": "unknown",
            },
        ),
        "optimization_opportunity": EnumDef(
            "OptimizationOpportunity",
            {
                "IMMEDIATE": "immediate",
                "SHORT_TERM": "short_term",
                "MEDIUM_TERM": "medium_term",
                "LONG_TERM": "long_term",
                "STRATEGIC": "strategic",
            },
        ),
    },
)

# Backward-compatible re-exports
CostDriver = PredictiveCostIntelligence.CostDriver
CostForecast = PredictiveCostIntelligence.CostForecast
OptimizationOpportunity = PredictiveCostIntelligence.OptimizationOpportunity
PredictiveCostIntelligenceRecord = PredictiveCostIntelligence.Record
PredictiveCostIntelligenceAnalysis = PredictiveCostIntelligence.Analysis
PredictiveCostIntelligenceReport = PredictiveCostIntelligence.Report
