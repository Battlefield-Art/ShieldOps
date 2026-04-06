"""Agent Resource Efficiency Engine — token, API call, compute optimization."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentResourceEfficiencyEngine = engine(
    "AgentResourceEfficiencyEngine",
    description="Track and optimize agent resource efficiency — tokens, API calls, compute.",
    enums={
        "resource_metric": EnumDef(
            "ResourceMetric",
            {
                "TOKEN_USAGE": "token_usage",
                "API_CALLS": "api_calls",
                "COMPUTE_SECONDS": "compute_seconds",
                "MEMORY_PEAK": "memory_peak",
            },
        ),
        "grade": EnumDef(
            "EfficiencyGrade",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
        "optimization_target": EnumDef(
            "OptimizationTarget",
            {
                "REDUCE_TOKENS": "reduce_tokens",
                "REDUCE_LATENCY": "reduce_latency",
                "REDUCE_COST": "reduce_cost",
                "IMPROVE_ACCURACY": "improve_accuracy",
            },
        ),
    },
    record_fields=[
        FieldDef("usage_value", float, 0.0),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
ResourceMetric = AgentResourceEfficiencyEngine.ResourceMetric
EfficiencyGrade = AgentResourceEfficiencyEngine.EfficiencyGrade
OptimizationTarget = AgentResourceEfficiencyEngine.OptimizationTarget
EfficiencyRecord = AgentResourceEfficiencyEngine.Record
EfficiencyAnalysis = AgentResourceEfficiencyEngine.Analysis
EfficiencyReport = AgentResourceEfficiencyEngine.Report
