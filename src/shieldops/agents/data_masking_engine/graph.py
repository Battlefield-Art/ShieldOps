"""Data Masking Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.data_masking_engine.models import DataMaskingEngineState
from shieldops.agents.data_masking_engine.nodes import (
    apply_masks,
    classify_sensitivity,
    discover_data,
    report,
    select_technique,
    validate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "data_masking_engine"


def _check_error(state: DataMaskingEngineState) -> str:
    return "report" if state.error else "next"


def create_data_masking_engine_graph() -> StateGraph:
    """Build the Data Masking Engine workflow."""
    graph = StateGraph(DataMaskingEngineState)

    graph.add_node(
        "discover_data",
        traced_node(f"{_AGENT}.discover_data", _AGENT)(discover_data),
    )
    graph.add_node(
        "classify_sensitivity",
        traced_node(f"{_AGENT}.classify_sensitivity", _AGENT)(classify_sensitivity),
    )
    graph.add_node(
        "select_technique",
        traced_node(f"{_AGENT}.select_technique", _AGENT)(select_technique),
    )
    graph.add_node(
        "apply_masks",
        traced_node(f"{_AGENT}.apply_masks", _AGENT)(apply_masks),
    )
    graph.add_node(
        "validate",
        traced_node(f"{_AGENT}.validate", _AGENT)(validate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_data")

    graph.add_conditional_edges(
        "discover_data",
        _check_error,
        {"next": "classify_sensitivity", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_sensitivity",
        _check_error,
        {"next": "select_technique", "report": "report"},
    )
    graph.add_conditional_edges(
        "select_technique",
        _check_error,
        {"next": "apply_masks", "report": "report"},
    )
    graph.add_conditional_edges(
        "apply_masks",
        _check_error,
        {"next": "validate", "report": "report"},
    )
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph
