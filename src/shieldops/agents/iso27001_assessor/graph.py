"""ISO 27001 Assessor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.iso27001_assessor.models import ISO27001AssessorState
from shieldops.agents.iso27001_assessor.nodes import (
    assess_controls,
    identify_gaps,
    report,
    risk_treatment,
    scope_isms,
    soa,
)
from shieldops.agents.tracing import traced_node

_AGENT = "iso27001_assessor"


def _check_error(state: ISO27001AssessorState) -> str:
    return "report" if state.error else "next"


def create_iso27001_assessor_graph() -> StateGraph:
    """Build the ISO 27001 Assessor LangGraph workflow."""
    graph = StateGraph(ISO27001AssessorState)

    graph.add_node(
        "scope_isms",
        traced_node(f"{_AGENT}.scope_isms", _AGENT)(scope_isms),
    )
    graph.add_node(
        "assess_controls",
        traced_node(f"{_AGENT}.assess_controls", _AGENT)(assess_controls),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "risk_treatment",
        traced_node(f"{_AGENT}.risk_treatment", _AGENT)(risk_treatment),
    )
    graph.add_node(
        "soa",
        traced_node(f"{_AGENT}.soa", _AGENT)(soa),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("scope_isms")

    graph.add_conditional_edges(
        "scope_isms",
        _check_error,
        {"next": "assess_controls", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_controls",
        _check_error,
        {"next": "identify_gaps", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_gaps",
        _check_error,
        {"next": "risk_treatment", "report": "report"},
    )
    graph.add_conditional_edges(
        "risk_treatment",
        _check_error,
        {"next": "soa", "report": "report"},
    )
    graph.add_edge("soa", "report")
    graph.add_edge("report", END)

    return graph
