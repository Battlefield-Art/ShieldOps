"""Communication Auditor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.communication_auditor.models import CommunicationAuditorState
from shieldops.agents.communication_auditor.nodes import (
    check_compliance,
    classify,
    collect_messages,
    flag_violations,
    generate_report,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "communication_auditor"


def _check_error(state: CommunicationAuditorState) -> str:
    return "report" if state.error else "next"


def create_communication_auditor_graph() -> StateGraph:
    """Build the Communication Auditor LangGraph workflow."""
    graph = StateGraph(CommunicationAuditorState)

    graph.add_node(
        "collect_messages",
        traced_node(f"{_AGENT}.collect_messages", _AGENT)(collect_messages),
    )
    graph.add_node(
        "classify",
        traced_node(f"{_AGENT}.classify", _AGENT)(classify),
    )
    graph.add_node(
        "check_compliance",
        traced_node(f"{_AGENT}.check_compliance", _AGENT)(check_compliance),
    )
    graph.add_node(
        "flag_violations",
        traced_node(f"{_AGENT}.flag_violations", _AGENT)(flag_violations),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_messages")

    graph.add_conditional_edges(
        "collect_messages",
        _check_error,
        {"next": "classify", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify",
        _check_error,
        {"next": "check_compliance", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_compliance",
        _check_error,
        {"next": "flag_violations", "report": "report"},
    )
    graph.add_conditional_edges(
        "flag_violations",
        _check_error,
        {"next": "generate_report", "report": "report"},
    )
    graph.add_edge("generate_report", "report")
    graph.add_edge("report", END)

    return graph
