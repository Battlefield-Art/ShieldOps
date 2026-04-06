"""Evolution Iteration Optimizer Engine — optimizes number of co-evolution iterations and reso..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EvolutionIterationOptimizerEngine = engine(
    "EvolutionIterationOptimizerEngine",
    description="Optimizes number of co-evolution iterations and resource allocation.",
    enums={
        "strategy": EnumDef(
            "OptimizationStrategy",
            {
                "FIXED_BUDGET": "fixed_budget",
                "ADAPTIVE_BUDGET": "adaptive_budget",
                "DIMINISHING_RETURNS": "diminishing_returns",
                "GREEDY": "greedy",
            },
        ),
        "allocation": EnumDef(
            "ResourceAllocation",
            {
                "COMPUTE_HEAVY": "compute_heavy",
                "BALANCED": "balanced",
                "MEMORY_HEAVY": "memory_heavy",
                "MINIMAL": "minimal",
            },
        ),
        "efficiency": EnumDef(
            "IterationEfficiency",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "WASTEFUL": "wasteful",
                "INSUFFICIENT": "insufficient",
            },
        ),
    },
    record_fields=[
        FieldDef("iteration", int, 0),
        FieldDef("cost_per_iteration", float, 0.0),
        FieldDef("improvement_gain", float, 0.0),
        FieldDef("compute_units", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="run_id",
)

# Backward-compatible re-exports
OptimizationStrategy = EvolutionIterationOptimizerEngine.OptimizationStrategy
ResourceAllocation = EvolutionIterationOptimizerEngine.ResourceAllocation
IterationEfficiency = EvolutionIterationOptimizerEngine.IterationEfficiency
IterationOptimizerRecord = EvolutionIterationOptimizerEngine.Record
IterationOptimizerAnalysis = EvolutionIterationOptimizerEngine.Analysis
IterationOptimizerReport = EvolutionIterationOptimizerEngine.Report
