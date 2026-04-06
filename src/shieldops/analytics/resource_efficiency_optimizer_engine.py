"""ResourceEfficiencyOptimizerEngine — optimize agent resource usage."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceEfficiencyOptimizerEngine = engine(
    "ResourceEfficiencyOptimizerEngine",
    description="Optimize agent resource usage (LLM tokens, compute, memory).",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "LLM_TOKENS": "llm_tokens",
                "COMPUTE_SECONDS": "compute_seconds",
                "MEMORY_MB": "memory_mb",
                "API_CALLS": "api_calls",
            },
        ),
        "optimization_goal": EnumDef(
            "OptimizationGoal",
            {
                "MINIMIZE_COST": "minimize_cost",
                "MAXIMIZE_THROUGHPUT": "maximize_throughput",
                "BALANCE": "balance",
            },
        ),
        "efficiency_trend": EnumDef(
            "EfficiencyTrend",
            {
                "IMPROVING": "improving",
                "DEGRADING": "degrading",
                "PLATEAU": "plateau",
            },
        ),
    },
    record_fields=[
        FieldDef("resource_used", float, 0.0),
        FieldDef("resource_budget", float, 0.0),
        FieldDef("cost_usd", float, 0.0),
        FieldDef("agent_id", str, ""),
    ],
)

# Backward-compatible re-exports
ResourceType = ResourceEfficiencyOptimizerEngine.ResourceType
OptimizationGoal = ResourceEfficiencyOptimizerEngine.OptimizationGoal
EfficiencyTrend = ResourceEfficiencyOptimizerEngine.EfficiencyTrend
ResourceEfficiencyOptimizerRecord = ResourceEfficiencyOptimizerEngine.Record
ResourceEfficiencyOptimizerAnalysis = ResourceEfficiencyOptimizerEngine.Analysis
ResourceEfficiencyOptimizerReport = ResourceEfficiencyOptimizerEngine.Report
