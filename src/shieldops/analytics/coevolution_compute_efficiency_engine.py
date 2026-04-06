"""Coevolution Compute Efficiency Engine — measures compute efficiency of co-evolution (HRPO v..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CoevolutionComputeEfficiencyEngine = engine(
    "CoevolutionComputeEfficiencyEngine",
    description="Measures compute efficiency of co-evolution (HRPO vs GRPO comparison).",
    enums={
        "grouping": EnumDef(
            "GroupingStrategy",
            {
                "HOP_GROUPED": "hop_grouped",
                "RANDOM_GROUPED": "random_grouped",
                "UNGROUPED": "ungrouped",
                "ADAPTIVE_GROUPED": "adaptive_grouped",
            },
        ),
        "batch_config": EnumDef(
            "BatchConfiguration",
            {
                "SMALL_BATCH": "small_batch",
                "MEDIUM_BATCH": "medium_batch",
                "LARGE_BATCH": "large_batch",
                "DYNAMIC_BATCH": "dynamic_batch",
            },
        ),
        "metric": EnumDef(
            "EfficiencyMetric",
            {
                "THROUGHPUT": "throughput",
                "LATENCY": "latency",
                "COST_PER_SAMPLE": "cost_per_sample",
                "MEMORY_USAGE": "memory_usage",
            },
        ),
    },
    record_fields=[
        FieldDef("throughput", float, 0.0),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("cost_per_sample", float, 0.0),
        FieldDef("memory_gb", float, 0.0),
        FieldDef("speedup_ratio", float, 1.0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
GroupingStrategy = CoevolutionComputeEfficiencyEngine.GroupingStrategy
BatchConfiguration = CoevolutionComputeEfficiencyEngine.BatchConfiguration
EfficiencyMetric = CoevolutionComputeEfficiencyEngine.EfficiencyMetric
ComputeEfficiencyRecord = CoevolutionComputeEfficiencyEngine.Record
ComputeEfficiencyAnalysis = CoevolutionComputeEfficiencyEngine.Analysis
ComputeEfficiencyReport = CoevolutionComputeEfficiencyEngine.Report
