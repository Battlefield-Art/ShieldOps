"""Hunt Hypothesis Generator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.hunt_hypothesis_generator.models import HuntHypothesisGeneratorState
from shieldops.agents.hunt_hypothesis_generator.nodes import (
    analyze_intel,
    create_queries,
    generate_hypotheses,
    identify_gaps,
    prioritize,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "hunt_hypothesis_generator"


def _check_error(state: HuntHypothesisGeneratorState) -> str:
    return "report" if state.error else "next"


def create_hunt_hypothesis_generator_graph() -> StateGraph:
    """Build the Hunt Hypothesis Generator workflow."""
    graph = StateGraph(HuntHypothesisGeneratorState)

    graph.add_node(
        "analyze_intel",
        traced_node(f"{_AGENT}.analyze_intel", _AGENT)(analyze_intel),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "generate_hypotheses",
        traced_node(f"{_AGENT}.generate_hypotheses", _AGENT)(generate_hypotheses),
    )
    graph.add_node(
        "prioritize",
        traced_node(f"{_AGENT}.prioritize", _AGENT)(prioritize),
    )
    graph.add_node(
        "create_queries",
        traced_node(f"{_AGENT}.create_queries", _AGENT)(create_queries),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("analyze_intel")

    graph.add_conditional_edges(
        "analyze_intel",
        _check_error,
        {"next": "identify_gaps", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_gaps",
        _check_error,
        {"next": "generate_hypotheses", "report": "report"},
    )
    graph.add_conditional_edges(
        "generate_hypotheses",
        _check_error,
        {"next": "prioritize", "report": "report"},
    )
    graph.add_conditional_edges(
        "prioritize",
        _check_error,
        {"next": "create_queries", "report": "report"},
    )
    graph.add_edge("create_queries", "report")
    graph.add_edge("report", END)

    return graph
