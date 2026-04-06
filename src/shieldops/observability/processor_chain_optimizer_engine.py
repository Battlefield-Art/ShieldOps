"""Processor Chain Optimizer Engine — evaluate chain ordering, measure processor drop impact,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ProcessorChainOptimizerEngine = engine(
    "ProcessorChainOptimizerEngine",
    description="Evaluate chain ordering, measure processor drop impact, recommend chain sim...",
    enums={
        "processor_type": EnumDef(
            "ProcessorType",
            {
                "BATCH": "batch",
                "FILTER": "filter",
                "TRANSFORM": "transform",
                "SAMPLING": "sampling",
            },
        ),
        "chain_efficiency": EnumDef(
            "ChainEfficiency",
            {
                "OPTIMAL": "optimal",
                "SUBOPTIMAL": "suboptimal",
                "WASTEFUL": "wasteful",
                "BROKEN": "broken",
            },
        ),
        "optimization_goal": EnumDef(
            "OptimizationGoal",
            {
                "MINIMIZE_LATENCY": "minimize_latency",
                "MAXIMIZE_THROUGHPUT": "maximize_throughput",
                "REDUCE_COST": "reduce_cost",
                "IMPROVE_FIDELITY": "improve_fidelity",
            },
        ),
    },
    record_fields=[
        FieldDef("chain_position", int, 0),
        FieldDef("drop_rate_pct", float, 0.0),
        FieldDef("latency_added_ms", float, 0.0),
        FieldDef("throughput_items_per_sec", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="chain_id",
)

# Backward-compatible re-exports
ProcessorType = ProcessorChainOptimizerEngine.ProcessorType
ChainEfficiency = ProcessorChainOptimizerEngine.ChainEfficiency
OptimizationGoal = ProcessorChainOptimizerEngine.OptimizationGoal
ProcessorChainRecord = ProcessorChainOptimizerEngine.Record
ProcessorChainAnalysis = ProcessorChainOptimizerEngine.Analysis
ProcessorChainReport = ProcessorChainOptimizerEngine.Report
