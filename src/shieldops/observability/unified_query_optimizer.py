"""UnifiedQueryOptimizer — unified query optimizer."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

UnifiedQueryOptimizer = engine(
    "UnifiedQueryOptimizer",
    module="operations",  # uses record_item
    description="Unified Query Optimizer.",
    enums={
        "query_type": EnumDef(
            "QueryType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "COMPOSITE": "composite",
                "AGGREGATION": "aggregation",
            },
        ),
        "optimization_strategy": EnumDef(
            "OptimizationStrategy",
            {
                "INDEX_HINT": "index_hint",
                "PARTITION_PRUNING": "partition_pruning",
                "CACHE": "cache",
                "PARALLELISM": "parallelism",
                "SAMPLING": "sampling",
            },
        ),
        "query_complexity": EnumDef(
            "QueryComplexity",
            {
                "SIMPLE": "simple",
                "MODERATE": "moderate",
                "COMPLEX": "complex",
                "EXPENSIVE": "expensive",
                "EXTREME": "extreme",
            },
        ),
    },
)

# Backward-compatible re-exports
QueryType = UnifiedQueryOptimizer.QueryType
OptimizationStrategy = UnifiedQueryOptimizer.OptimizationStrategy
QueryComplexity = UnifiedQueryOptimizer.QueryComplexity
UnifiedQueryOptimizerRecord = UnifiedQueryOptimizer.Record
UnifiedQueryOptimizerAnalysis = UnifiedQueryOptimizer.Analysis
UnifiedQueryOptimizerReport = UnifiedQueryOptimizer.Report
