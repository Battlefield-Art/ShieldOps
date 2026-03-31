"""LangGraph workflow definition for the Privacy Rights
Automator Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.privacy_rights_automator.models import (
    PrivacyRightsAutomatorState,
)
from shieldops.agents.privacy_rights_automator.nodes import (
    classify_pii,
    generate_report,
    locate_data,
    process_action,
    receive_request,
    verify_completion,
)
from shieldops.agents.tracing import traced_node

_AGENT = "privacy_rights_automator"


def _should_process(
    state: PrivacyRightsAutomatorState,
) -> str:
    """Route after classification: process if data found
    and classified, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.data_locations and state.classifications:
        return "process_action"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Privacy Rights Automator LangGraph
    workflow.

    Workflow:
        receive_request -> locate_data -> classify_pii
            -> [data found? -> process_action
            -> verify_completion]
            -> generate_report -> END
    """
    graph = StateGraph(PrivacyRightsAutomatorState)

    graph.add_node(
        "receive_request",
        traced_node(f"{_AGENT}.receive_request", _AGENT)(receive_request),
    )
    graph.add_node(
        "locate_data",
        traced_node(f"{_AGENT}.locate_data", _AGENT)(locate_data),
    )
    graph.add_node(
        "classify_pii",
        traced_node(f"{_AGENT}.classify_pii", _AGENT)(classify_pii),
    )
    graph.add_node(
        "process_action",
        traced_node(f"{_AGENT}.process_action", _AGENT)(process_action),
    )
    graph.add_node(
        "verify_completion",
        traced_node(f"{_AGENT}.verify_completion", _AGENT)(verify_completion),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("receive_request")
    graph.add_edge("receive_request", "locate_data")
    graph.add_edge("locate_data", "classify_pii")
    graph.add_conditional_edges(
        "classify_pii",
        _should_process,
        {
            "process_action": "process_action",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("process_action", "verify_completion")
    graph.add_edge("verify_completion", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_privacy_rights_automator_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Privacy Rights Automator
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
