"""Analyst Efficiency Tracker — measure and optimize SOC analyst performance metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AnalystEfficiencyTracker = engine(
    "AnalystEfficiencyTracker",
    description="Measure and optimize SOC analyst performance metrics across tiers.",
    enums={
        "efficiency_metric": EnumDef(
            "EfficiencyMetric",
            {
                "MEAN_TIME_TO_TRIAGE": "mean_time_to_triage",
                "MEAN_TIME_TO_RESOLVE": "mean_time_to_resolve",
                "ALERTS_PER_ANALYST": "alerts_per_analyst",
                "FALSE_POSITIVE_RATE": "false_positive_rate",
                "ESCALATION_RATE": "escalation_rate",
            },
        ),
        "analyst_tier": EnumDef(
            "AnalystTier",
            {
                "TIER_1": "tier_1",
                "TIER_2": "tier_2",
                "TIER_3": "tier_3",
                "LEAD": "lead",
                "MANAGER": "manager",
            },
        ),
        "performance_band": EnumDef(
            "PerformanceBand",
            {
                "EXCEPTIONAL": "exceptional",
                "ABOVE_AVERAGE": "above_average",
                "AVERAGE": "average",
                "BELOW_AVERAGE": "below_average",
                "NEEDS_IMPROVEMENT": "needs_improvement",
            },
        ),
    },
    score_field="efficiency_score",
    key_field="analyst_name",
)

# Backward-compatible re-exports
EfficiencyMetric = AnalystEfficiencyTracker.EfficiencyMetric
AnalystTier = AnalystEfficiencyTracker.AnalystTier
PerformanceBand = AnalystEfficiencyTracker.PerformanceBand
EfficiencyRecord = AnalystEfficiencyTracker.Record
EfficiencyAnalysis = AnalystEfficiencyTracker.Analysis
EfficiencyReport = AnalystEfficiencyTracker.Report
