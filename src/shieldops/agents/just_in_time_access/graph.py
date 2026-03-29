"""Just In Time Access Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.just_in_time_access.models import JustInTimeAccessState
from shieldops.agents.just_in_time_access.nodes import (
    evaluate_policy,
    monitor_session,
    provision_access,
    receive_request,
    report,
    revoke_access,
)
from shieldops.agents.tracing import traced_node

_AGENT = "just_in_time_access"


def _check_error(state: JustInTimeAccessState) -> str:
    return "report" if state.error else "next"


def create_just_in_time_access_graph() -> StateGraph:
    """Build the Just In Time Access workflow."""
    graph = StateGraph(JustInTimeAccessState)

    graph.add_node(
        "receive_request",
        traced_node(f"{_AGENT}.receive_request", _AGENT)(receive_request),
    )
    graph.add_node(
        "evaluate_policy",
        traced_node(f"{_AGENT}.evaluate_policy", _AGENT)(evaluate_policy),
    )
    graph.add_node(
        "provision_access",
        traced_node(f"{_AGENT}.provision_access", _AGENT)(provision_access),
    )
    graph.add_node(
        "monitor_session",
        traced_node(f"{_AGENT}.monitor_session", _AGENT)(monitor_session),
    )
    graph.add_node(
        "revoke_access",
        traced_node(f"{_AGENT}.revoke_access", _AGENT)(revoke_access),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("receive_request")

    graph.add_conditional_edges(
        "receive_request",
        _check_error,
        {"next": "evaluate_policy", "report": "report"},
    )
    graph.add_conditional_edges(
        "evaluate_policy",
        _check_error,
        {"next": "provision_access", "report": "report"},
    )
    graph.add_conditional_edges(
        "provision_access",
        _check_error,
        {"next": "monitor_session", "report": "report"},
    )
    graph.add_conditional_edges(
        "monitor_session",
        _check_error,
        {"next": "revoke_access", "report": "report"},
    )
    graph.add_edge("revoke_access", "report")
    graph.add_edge("report", END)

    return graph
