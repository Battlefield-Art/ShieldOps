"""OtelServiceGraphEngine — OTel service graph engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OtelServiceGraphEngine = engine(
    "OtelServiceGraphEngine",
    module="operations",  # uses record_item
    description="OTel service graph engine.",
    enums={
        "graph_source": EnumDef(
            "GraphSource",
            {
                "TRACE_SPANS": "trace_spans",
                "METRICS": "metrics",
                "LOGS": "logs",
                "MANUAL": "manual",
            },
        ),
        "edge_type": EnumDef(
            "EdgeType",
            {
                "HTTP": "http",
                "GRPC": "grpc",
                "KAFKA": "kafka",
                "DATABASE": "database",
            },
        ),
        "graph_freshness": EnumDef(
            "GraphFreshness",
            {
                "REALTIME": "realtime",
                "RECENT": "recent",
                "STALE": "stale",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
GraphSource = OtelServiceGraphEngine.GraphSource
EdgeType = OtelServiceGraphEngine.EdgeType
GraphFreshness = OtelServiceGraphEngine.GraphFreshness
OtelServiceGraphEngineRecord = OtelServiceGraphEngine.Record
OtelServiceGraphEngineAnalysis = OtelServiceGraphEngine.Analysis
OtelServiceGraphEngineReport = OtelServiceGraphEngine.Report
