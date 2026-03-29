"""Security Copilot Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_copilot.models import SecurityCopilotState
from shieldops.agents.security_copilot.nodes import (
    analyze_data,
    generate_response,
    parse_query,
    report,
    search_context,
    validate_accuracy,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_copilot"


def _check_error(state: SecurityCopilotState) -> str:
    return "report" if state.error else "next"


def create_security_copilot_graph() -> StateGraph:
    """Build the Security Copilot workflow."""
    graph = StateGraph(SecurityCopilotState)

    graph.add_node(
        "parse_query",
        traced_node(f"{_AGENT}.parse_query", _AGENT)(parse_query),
    )
    graph.add_node(
        "search_context",
        traced_node(f"{_AGENT}.search_context", _AGENT)(search_context),
    )
    graph.add_node(
        "analyze_data",
        traced_node(f"{_AGENT}.analyze_data", _AGENT)(analyze_data),
    )
    graph.add_node(
        "generate_response",
        traced_node(f"{_AGENT}.generate_response", _AGENT)(generate_response),
    )
    graph.add_node(
        "validate_accuracy",
        traced_node(f"{_AGENT}.validate_accuracy", _AGENT)(validate_accuracy),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("parse_query")

    graph.add_conditional_edges(
        "parse_query",
        _check_error,
        {"next": "search_context", "report": "report"},
    )
    graph.add_conditional_edges(
        "search_context",
        _check_error,
        {"next": "analyze_data", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_data",
        _check_error,
        {"next": "generate_response", "report": "report"},
    )
    graph.add_conditional_edges(
        "generate_response",
        _check_error,
        {"next": "validate_accuracy", "report": "report"},
    )
    graph.add_edge("validate_accuracy", "report")
    graph.add_edge("report", END)

    return graph
