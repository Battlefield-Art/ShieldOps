"""Log Query Optimizer — optimize queries, measure latency, recommend indexes."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LogQueryOptimizer = engine(
    "LogQueryOptimizer",
    description="Optimize log queries, measure latency, and recommend indexes.",
    enums={
        "query_type": EnumDef(
            "QueryType",
            {
                "FULL_TEXT": "full_text",
                "AGGREGATION": "aggregation",
                "FILTER": "filter",
                "REGEX": "regex",
                "STRUCTURED": "structured",
            },
        ),
        "optimization_method": EnumDef(
            "OptimizationMethod",
            {
                "INDEX_HINT": "index_hint",
                "QUERY_REWRITE": "query_rewrite",
                "PARTITION_PRUNE": "partition_prune",
                "CACHE_HIT": "cache_hit",
                "PARALLEL_SCAN": "parallel_scan",
            },
        ),
        "performance_tier": EnumDef(
            "PerformanceTier",
            {
                "FAST": "fast",
                "ACCEPTABLE": "acceptable",
                "SLOW": "slow",
                "CRITICAL": "critical",
                "TIMEOUT": "timeout",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
    ],
    key_field="query_name",
)

# Backward-compatible re-exports
QueryType = LogQueryOptimizer.QueryType
OptimizationMethod = LogQueryOptimizer.OptimizationMethod
PerformanceTier = LogQueryOptimizer.PerformanceTier
QueryRecord = LogQueryOptimizer.Record
QueryAnalysis = LogQueryOptimizer.Analysis
QueryReport = LogQueryOptimizer.Report
