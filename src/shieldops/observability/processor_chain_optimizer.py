"""ProcessorChainOptimizer — processor chain optimization."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ProcessorChainOptimizer = engine(
    "ProcessorChainOptimizer",
    description="Processor chain optimization engine.",
    enums={
        "processor_type": EnumDef(
            "ProcessorType",
            {
                "BATCH": "batch",
                "FILTER": "filter",
                "TRANSFORM": "transform",
                "ENRICH": "enrich",
            },
        ),
        "chain_position": EnumDef(
            "ChainPosition",
            {
                "EARLY": "early",
                "MIDDLE": "middle",
                "LATE": "late",
                "TERMINAL": "terminal",
            },
        ),
        "optimization_goal": EnumDef(
            "OptimizationGoal",
            {
                "THROUGHPUT": "throughput",
                "LATENCY": "latency",
                "ACCURACY": "accuracy",
                "COST": "cost",
            },
        ),
    },
)

# Backward-compatible re-exports
ProcessorType = ProcessorChainOptimizer.ProcessorType
ChainPosition = ProcessorChainOptimizer.ChainPosition
OptimizationGoal = ProcessorChainOptimizer.OptimizationGoal
ProcessorChainOptimizerRecord = ProcessorChainOptimizer.Record
ProcessorChainOptimizerAnalysis = ProcessorChainOptimizer.Analysis
ProcessorChainOptimizerReport = ProcessorChainOptimizer.Report
