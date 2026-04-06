"""Adaptive Retrieval Strategy Engine — decide which monitoring tool/data source to query next..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdaptiveRetrievalStrategyEngine = engine(
    "AdaptiveRetrievalStrategyEngine",
    description="Decide which monitoring tool/data source to query next, evaluate retrieval...",
    enums={
        "data_source": EnumDef(
            "DataSource",
            {
                "METRICS": "metrics",
                "LOGS": "logs",
                "TRACES": "traces",
                "EVENTS": "events",
            },
        ),
        "retrieval_strategy": EnumDef(
            "RetrievalStrategy",
            {
                "BREADTH_FIRST": "breadth_first",
                "DEPTH_FIRST": "depth_first",
                "PRIORITY_GUIDED": "priority_guided",
                "COST_AWARE": "cost_aware",
            },
        ),
        "query_outcome": EnumDef(
            "QueryOutcome",
            {
                "HIGH_SIGNAL": "high_signal",
                "LOW_SIGNAL": "low_signal",
                "NO_SIGNAL": "no_signal",
                "AMBIGUOUS": "ambiguous",
            },
        ),
    },
    record_fields=[
        FieldDef("query_cost_ms", float, 0.0),
        FieldDef("query_text", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="signal_score",
    key_field="session_id",
)

# Backward-compatible re-exports
DataSource = AdaptiveRetrievalStrategyEngine.DataSource
RetrievalStrategy = AdaptiveRetrievalStrategyEngine.RetrievalStrategy
QueryOutcome = AdaptiveRetrievalStrategyEngine.QueryOutcome
AdaptiveRetrievalRecord = AdaptiveRetrievalStrategyEngine.Record
AdaptiveRetrievalAnalysis = AdaptiveRetrievalStrategyEngine.Analysis
AdaptiveRetrievalReport = AdaptiveRetrievalStrategyEngine.Report
