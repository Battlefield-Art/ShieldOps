"""Data Breach Responder Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.data_breach_responder.models import DataBreachResponderState
from shieldops.agents.data_breach_responder.nodes import (
    assess_scope,
    contain,
    detect_breach,
    notify_authorities,
    notify_subjects,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "data_breach_responder"


def _check_error(state: DataBreachResponderState) -> str:
    return "report" if state.error else "next"


def create_data_breach_responder_graph() -> StateGraph:
    """Build the Data Breach Responder workflow."""
    graph = StateGraph(DataBreachResponderState)

    graph.add_node(
        "detect_breach",
        traced_node(f"{_AGENT}.detect_breach", _AGENT)(detect_breach),
    )
    graph.add_node(
        "assess_scope",
        traced_node(f"{_AGENT}.assess_scope", _AGENT)(assess_scope),
    )
    graph.add_node(
        "contain",
        traced_node(f"{_AGENT}.contain", _AGENT)(contain),
    )
    graph.add_node(
        "notify_authorities",
        traced_node(f"{_AGENT}.notify_authorities", _AGENT)(notify_authorities),
    )
    graph.add_node(
        "notify_subjects",
        traced_node(f"{_AGENT}.notify_subjects", _AGENT)(notify_subjects),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("detect_breach")

    graph.add_conditional_edges(
        "detect_breach",
        _check_error,
        {"next": "assess_scope", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_scope",
        _check_error,
        {"next": "contain", "report": "report"},
    )
    graph.add_conditional_edges(
        "contain",
        _check_error,
        {"next": "notify_authorities", "report": "report"},
    )
    graph.add_conditional_edges(
        "notify_authorities",
        _check_error,
        {"next": "notify_subjects", "report": "report"},
    )
    graph.add_edge("notify_subjects", "report")
    graph.add_edge("report", END)

    return graph
