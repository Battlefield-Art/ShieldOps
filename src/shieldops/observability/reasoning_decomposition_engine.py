"""Reasoning Decomposition Engine — decompose complex investigations into sub-queries, compose..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReasoningDecompositionEngine = engine(
    "ReasoningDecompositionEngine",
    description="Decompose complex investigations into sub-queries, compose sub-results, opt...",
    enums={
        "decomposition_method": EnumDef(
            "DecompositionMethod",
            {
                "HIERARCHICAL": "hierarchical",
                "PARALLEL": "parallel",
                "SEQUENTIAL": "sequential",
                "HYBRID": "hybrid",
            },
        ),
        "sub_query_complexity": EnumDef(
            "SubQueryComplexity",
            {
                "ATOMIC": "atomic",
                "SIMPLE": "simple",
                "COMPOUND": "compound",
                "RECURSIVE": "recursive",
            },
        ),
        "composition_strategy": EnumDef(
            "CompositionStrategy",
            {
                "MERGE": "merge",
                "CHAIN": "chain",
                "VOTE": "vote",
                "WEIGHTED": "weighted",
            },
        ),
    },
    record_fields=[
        FieldDef("sub_query_count", int, 1),
        FieldDef("sub_query_text", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="resolution_score",
    key_field="investigation_id",
)

# Backward-compatible re-exports
DecompositionMethod = ReasoningDecompositionEngine.DecompositionMethod
SubQueryComplexity = ReasoningDecompositionEngine.SubQueryComplexity
CompositionStrategy = ReasoningDecompositionEngine.CompositionStrategy
ReasoningDecompositionRecord = ReasoningDecompositionEngine.Record
ReasoningDecompositionAnalysis = ReasoningDecompositionEngine.Analysis
ReasoningDecompositionReport = ReasoningDecompositionEngine.Report
