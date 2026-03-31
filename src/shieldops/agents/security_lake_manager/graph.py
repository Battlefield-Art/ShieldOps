"""LangGraph workflow definition for the Security Lake
Manager Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_lake_manager.models import (
    SecurityLakeState,
)
from shieldops.agents.security_lake_manager.nodes import (
    discover_sources,
    generate_report,
    ingest_data,
    normalize_schema,
    optimize_storage,
    query_analytics,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_lake_manager"


def _should_optimize(
    state: SecurityLakeState,
) -> str:
    """Route after normalization: optimize if data
    exists, otherwise skip to analytics."""
    if state.error:
        return "generate_report"
    if len(state.ingestion_records) > 0:
        return "optimize_storage"
    return "query_analytics"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Lake Manager workflow.

    Workflow:
        discover_sources -> ingest_data -> normalize_schema
            -> [data? -> optimize_storage] -> query_analytics
            -> generate_report -> END
    """
    graph = StateGraph(SecurityLakeState)

    graph.add_node(
        "discover_sources",
        traced_node(f"{_AGENT}.discover_sources", _AGENT)(discover_sources),
    )
    graph.add_node(
        "ingest_data",
        traced_node(f"{_AGENT}.ingest_data", _AGENT)(ingest_data),
    )
    graph.add_node(
        "normalize_schema",
        traced_node(f"{_AGENT}.normalize_schema", _AGENT)(normalize_schema),
    )
    graph.add_node(
        "optimize_storage",
        traced_node(f"{_AGENT}.optimize_storage", _AGENT)(optimize_storage),
    )
    graph.add_node(
        "query_analytics",
        traced_node(f"{_AGENT}.query_analytics", _AGENT)(query_analytics),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("discover_sources")
    graph.add_edge("discover_sources", "ingest_data")
    graph.add_edge("ingest_data", "normalize_schema")
    graph.add_conditional_edges(
        "normalize_schema",
        _should_optimize,
        {
            "optimize_storage": "optimize_storage",
            "query_analytics": "query_analytics",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("optimize_storage", "query_analytics")
    graph.add_edge("query_analytics", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_lake_manager_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Lake Manager graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
