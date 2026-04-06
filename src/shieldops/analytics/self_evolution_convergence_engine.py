"""Self Evolution Convergence Engine — monitors convergence of the self-evolution loop."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SelfEvolutionConvergenceEngine = engine(
    "SelfEvolutionConvergenceEngine",
    description="Monitors convergence of the self-evolution loop.",
    enums={
        "status": EnumDef(
            "ConvergenceStatus",
            {
                "PRE_CONVERGENCE": "pre_convergence",
                "APPROACHING": "approaching",
                "CONVERGED": "converged",
                "DIVERGING": "diverging",
            },
        ),
        "criterion": EnumDef(
            "StoppingCriterion",
            {
                "REWARD_PLATEAU": "reward_plateau",
                "ITERATION_LIMIT": "iteration_limit",
                "PERFORMANCE_CEILING": "performance_ceiling",
                "COST_THRESHOLD": "cost_threshold",
            },
        ),
        "speed": EnumDef(
            "ConvergenceSpeed",
            {
                "FAST": "fast",
                "MODERATE": "moderate",
                "SLOW": "slow",
                "STALLED": "stalled",
            },
        ),
    },
    record_fields=[
        FieldDef("iteration", int, 0),
        FieldDef("reward_value", float, 0.0),
        FieldDef("reward_delta", float, 0.0),
        FieldDef("cost_incurred", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="evolution_id",
)

# Backward-compatible re-exports
ConvergenceStatus = SelfEvolutionConvergenceEngine.ConvergenceStatus
StoppingCriterion = SelfEvolutionConvergenceEngine.StoppingCriterion
ConvergenceSpeed = SelfEvolutionConvergenceEngine.ConvergenceSpeed
ConvergenceRecord = SelfEvolutionConvergenceEngine.Record
ConvergenceAnalysis = SelfEvolutionConvergenceEngine.Analysis
ConvergenceReport = SelfEvolutionConvergenceEngine.Report
