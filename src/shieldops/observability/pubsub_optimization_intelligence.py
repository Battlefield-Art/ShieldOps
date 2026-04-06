"""Pubsub Optimization Intelligence — optimize partition distribution, detect hot partitions,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PubsubOptimizationIntelligence = engine(
    "PubsubOptimizationIntelligence",
    description="Optimize partition distribution, detect hot partitions, rank topics by reba...",
    enums={
        "partition_strategy": EnumDef(
            "PartitionStrategy",
            {
                "KEY_BASED": "key_based",
                "ROUND_ROBIN": "round_robin",
                "CUSTOM": "custom",
                "HASH": "hash",
            },
        ),
        "distribution_health": EnumDef(
            "DistributionHealth",
            {
                "BALANCED": "balanced",
                "SKEWED": "skewed",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
        "optimization_action": EnumDef(
            "OptimizationAction",
            {
                "REBALANCE": "rebalance",
                "SPLIT": "split",
                "MERGE": "merge",
                "MAINTAIN": "maintain",
            },
        ),
    },
    record_fields=[
        FieldDef("partition_count", int, 0),
        FieldDef("skew_ratio", float, 0.0),
        FieldDef("throughput", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="topic_name",
)

# Backward-compatible re-exports
PartitionStrategy = PubsubOptimizationIntelligence.PartitionStrategy
DistributionHealth = PubsubOptimizationIntelligence.DistributionHealth
OptimizationAction = PubsubOptimizationIntelligence.OptimizationAction
PubsubOptRecord = PubsubOptimizationIntelligence.Record
PubsubOptAnalysis = PubsubOptimizationIntelligence.Analysis
PubsubOptReport = PubsubOptimizationIntelligence.Report
