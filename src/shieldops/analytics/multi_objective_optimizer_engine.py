"""Multi-Objective Optimizer Engine — find Pareto frontiers, evaluate tradeoff strategies, and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MultiObjectiveOptimizerEngine = engine(
    "MultiObjectiveOptimizerEngine",
    description="Balance competing optimization objectives, find Pareto frontiers, and rank...",
    enums={
        "objective_type": EnumDef(
            "ObjectiveType",
            {
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "COST": "cost",
                "RELIABILITY": "reliability",
            },
        ),
        "tradeoff_strategy": EnumDef(
            "TradeoffStrategy",
            {
                "PARETO": "pareto",
                "WEIGHTED": "weighted",
                "LEXICOGRAPHIC": "lexicographic",
                "EPSILON_CONSTRAINT": "epsilon_constraint",
            },
        ),
        "status": EnumDef(
            "OptimizationStatus",
            {
                "OPTIMAL": "optimal",
                "SUBOPTIMAL": "suboptimal",
                "INFEASIBLE": "infeasible",
                "EXPLORING": "exploring",
            },
        ),
    },
    record_fields=[
        FieldDef("objective_value", float, 0.0),
        FieldDef("weight", float, 1.0),
        FieldDef("constraint_bound", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="solution_id",
)

# Backward-compatible re-exports
ObjectiveType = MultiObjectiveOptimizerEngine.ObjectiveType
TradeoffStrategy = MultiObjectiveOptimizerEngine.TradeoffStrategy
OptimizationStatus = MultiObjectiveOptimizerEngine.OptimizationStatus
MultiObjectiveRecord = MultiObjectiveOptimizerEngine.Record
MultiObjectiveAnalysis = MultiObjectiveOptimizerEngine.Analysis
MultiObjectiveReport = MultiObjectiveOptimizerEngine.Report
