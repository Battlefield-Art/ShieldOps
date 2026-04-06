"""AgentPromptOptimizerEngine — Optimize agent prompts based on outcome quality."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentPromptOptimizerEngine = engine(
    "AgentPromptOptimizerEngine",
    description="Optimize agent prompts based on outcome quality engine.",
    enums={
        "prompt_variant": EnumDef(
            "PromptVariant",
            {
                "BASELINE": "baseline",
                "CANDIDATE_A": "candidate_a",
                "CANDIDATE_B": "candidate_b",
                "CHAMPION": "champion",
            },
        ),
        "optimization_metric": EnumDef(
            "OptimizationMetric",
            {
                "ACCURACY": "accuracy",
                "LATENCY": "latency",
                "TOKEN_COST": "token_cost",
                "USER_SATISFACTION": "user_satisfaction",
            },
        ),
        "prompt_status": EnumDef(
            "PromptStatus",
            {
                "TESTING": "testing",
                "CHAMPION": "champion",
                "RETIRED": "retired",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("token_count", int, 0),
        FieldDef("invocation_count", int, 0),
    ],
)

# Backward-compatible re-exports
PromptVariant = AgentPromptOptimizerEngine.PromptVariant
OptimizationMetric = AgentPromptOptimizerEngine.OptimizationMetric
PromptStatus = AgentPromptOptimizerEngine.PromptStatus
AgentPromptOptimizerRecord = AgentPromptOptimizerEngine.Record
AgentPromptOptimizerAnalysis = AgentPromptOptimizerEngine.Analysis
AgentPromptOptimizerReport = AgentPromptOptimizerEngine.Report
