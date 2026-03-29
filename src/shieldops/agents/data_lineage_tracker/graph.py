"""Data Lineage Tracker Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.data_lineage_tracker.models import DataLineageTrackerState
from shieldops.agents.data_lineage_tracker.nodes import (
    detect_anomalies,
    discover_sources,
    map_transformations,
    report,
    trace_lineage,
    validate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "data_lineage_tracker"


def _check_error(state: DataLineageTrackerState) -> str:
    return "report" if state.error else "next"


def create_data_lineage_tracker_graph() -> StateGraph:
    """Build the Data Lineage Tracker workflow."""
    graph = StateGraph(DataLineageTrackerState)

    graph.add_node(
        "discover_sources",
        traced_node(f"{_AGENT}.discover_sources", _AGENT)(discover_sources),
    )
    graph.add_node(
        "map_transformations",
        traced_node(f"{_AGENT}.map_transformations", _AGENT)(map_transformations),
    )
    graph.add_node(
        "trace_lineage",
        traced_node(f"{_AGENT}.trace_lineage", _AGENT)(trace_lineage),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "validate",
        traced_node(f"{_AGENT}.validate", _AGENT)(validate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_sources")

    graph.add_conditional_edges(
        "discover_sources",
        _check_error,
        {"next": "map_transformations", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_transformations",
        _check_error,
        {"next": "trace_lineage", "report": "report"},
    )
    graph.add_conditional_edges(
        "trace_lineage",
        _check_error,
        {"next": "detect_anomalies", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {"next": "validate", "report": "report"},
    )
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph
