"""SOX Auditor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.sox_auditor.models import SOXAuditorState
from shieldops.agents.sox_auditor.nodes import (
    document,
    evaluate_deficiencies,
    identify_controls,
    remediate,
    report,
    test_controls,
)
from shieldops.agents.tracing import traced_node

_AGENT = "sox_auditor"


def _check_error(state: SOXAuditorState) -> str:
    return "report" if state.error else "next"


def create_sox_auditor_graph() -> StateGraph:
    """Build the SOX Auditor LangGraph workflow."""
    graph = StateGraph(SOXAuditorState)

    graph.add_node(
        "identify_controls",
        traced_node(f"{_AGENT}.identify_controls", _AGENT)(identify_controls),
    )
    graph.add_node(
        "test_controls",
        traced_node(f"{_AGENT}.test_controls", _AGENT)(test_controls),
    )
    graph.add_node(
        "evaluate_deficiencies",
        traced_node(f"{_AGENT}.evaluate_deficiencies", _AGENT)(evaluate_deficiencies),
    )
    graph.add_node(
        "remediate",
        traced_node(f"{_AGENT}.remediate", _AGENT)(remediate),
    )
    graph.add_node(
        "document",
        traced_node(f"{_AGENT}.document", _AGENT)(document),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("identify_controls")

    graph.add_conditional_edges(
        "identify_controls",
        _check_error,
        {"next": "test_controls", "report": "report"},
    )
    graph.add_conditional_edges(
        "test_controls",
        _check_error,
        {"next": "evaluate_deficiencies", "report": "report"},
    )
    graph.add_conditional_edges(
        "evaluate_deficiencies",
        _check_error,
        {"next": "remediate", "report": "report"},
    )
    graph.add_conditional_edges(
        "remediate",
        _check_error,
        {"next": "document", "report": "report"},
    )
    graph.add_edge("document", "report")
    graph.add_edge("report", END)

    return graph
