"""Security Architecture Reviewer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_architecture_reviewer.models import SecurityArchitectureReviewerState
from shieldops.agents.security_architecture_reviewer.nodes import (
    analyze_components,
    collect_design,
    evaluate_controls,
    identify_risks,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_architecture_reviewer"


def _check_error(state: SecurityArchitectureReviewerState) -> str:
    return "report" if state.error else "next"


def create_security_architecture_reviewer_graph() -> StateGraph:
    """Build the Security Architecture Reviewer workflow."""
    graph = StateGraph(SecurityArchitectureReviewerState)

    graph.add_node(
        "collect_design",
        traced_node(f"{_AGENT}.collect_design", _AGENT)(collect_design),
    )
    graph.add_node(
        "analyze_components",
        traced_node(f"{_AGENT}.analyze_components", _AGENT)(analyze_components),
    )
    graph.add_node(
        "identify_risks",
        traced_node(f"{_AGENT}.identify_risks", _AGENT)(identify_risks),
    )
    graph.add_node(
        "evaluate_controls",
        traced_node(f"{_AGENT}.evaluate_controls", _AGENT)(evaluate_controls),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_design")

    graph.add_conditional_edges(
        "collect_design",
        _check_error,
        {"next": "analyze_components", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_components",
        _check_error,
        {"next": "identify_risks", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_risks",
        _check_error,
        {"next": "evaluate_controls", "report": "report"},
    )
    graph.add_conditional_edges(
        "evaluate_controls",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
