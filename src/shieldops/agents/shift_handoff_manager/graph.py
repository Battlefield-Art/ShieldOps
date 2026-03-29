"""Shift Handoff Manager Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.shift_handoff_manager.models import ShiftHandoffManagerState
from shieldops.agents.shift_handoff_manager.nodes import (
    brief_incoming,
    collect_state,
    document_actions,
    report,
    summarize_incidents,
    transfer,
)
from shieldops.agents.tracing import traced_node

_AGENT = "shift_handoff_manager"


def _check_error(state: ShiftHandoffManagerState) -> str:
    return "report" if state.error else "next"


def create_shift_handoff_manager_graph() -> StateGraph:
    """Build the Shift Handoff Manager workflow."""
    graph = StateGraph(ShiftHandoffManagerState)

    graph.add_node(
        "collect_state",
        traced_node(f"{_AGENT}.collect_state", _AGENT)(collect_state),
    )
    graph.add_node(
        "summarize_incidents",
        traced_node(f"{_AGENT}.summarize_incidents", _AGENT)(summarize_incidents),
    )
    graph.add_node(
        "document_actions",
        traced_node(f"{_AGENT}.document_actions", _AGENT)(document_actions),
    )
    graph.add_node(
        "brief_incoming",
        traced_node(f"{_AGENT}.brief_incoming", _AGENT)(brief_incoming),
    )
    graph.add_node(
        "transfer",
        traced_node(f"{_AGENT}.transfer", _AGENT)(transfer),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_state")

    graph.add_conditional_edges(
        "collect_state",
        _check_error,
        {"next": "summarize_incidents", "report": "report"},
    )
    graph.add_conditional_edges(
        "summarize_incidents",
        _check_error,
        {"next": "document_actions", "report": "report"},
    )
    graph.add_conditional_edges(
        "document_actions",
        _check_error,
        {"next": "brief_incoming", "report": "report"},
    )
    graph.add_conditional_edges(
        "brief_incoming",
        _check_error,
        {"next": "transfer", "report": "report"},
    )
    graph.add_edge("transfer", "report")
    graph.add_edge("report", END)

    return graph
