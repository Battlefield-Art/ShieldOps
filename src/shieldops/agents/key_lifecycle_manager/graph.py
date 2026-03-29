"""Key Lifecycle Manager Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.key_lifecycle_manager.models import KeyLifecycleManagerState
from shieldops.agents.key_lifecycle_manager.nodes import (
    assess_compliance,
    audit_ceremonies,
    check_rotation,
    discover_keys,
    report,
    track_escrow,
)
from shieldops.agents.tracing import traced_node

_AGENT = "key_lifecycle_manager"


def _check_error(state: KeyLifecycleManagerState) -> str:
    return "report" if state.error else "next"


def create_key_lifecycle_manager_graph() -> StateGraph:
    """Build the Key Lifecycle Manager workflow."""
    graph = StateGraph(KeyLifecycleManagerState)

    graph.add_node(
        "discover_keys",
        traced_node(f"{_AGENT}.discover_keys", _AGENT)(discover_keys),
    )
    graph.add_node(
        "audit_ceremonies",
        traced_node(f"{_AGENT}.audit_ceremonies", _AGENT)(audit_ceremonies),
    )
    graph.add_node(
        "check_rotation",
        traced_node(f"{_AGENT}.check_rotation", _AGENT)(check_rotation),
    )
    graph.add_node(
        "assess_compliance",
        traced_node(f"{_AGENT}.assess_compliance", _AGENT)(assess_compliance),
    )
    graph.add_node(
        "track_escrow",
        traced_node(f"{_AGENT}.track_escrow", _AGENT)(track_escrow),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_keys")

    graph.add_conditional_edges(
        "discover_keys",
        _check_error,
        {"next": "audit_ceremonies", "report": "report"},
    )
    graph.add_conditional_edges(
        "audit_ceremonies",
        _check_error,
        {"next": "check_rotation", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_rotation",
        _check_error,
        {"next": "assess_compliance", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_compliance",
        _check_error,
        {"next": "track_escrow", "report": "report"},
    )
    graph.add_edge("track_escrow", "report")
    graph.add_edge("report", END)

    return graph
