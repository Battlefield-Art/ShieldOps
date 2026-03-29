"""NIST Framework Mapper Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.nist_framework_mapper.models import NISTFrameworkMapperState
from shieldops.agents.nist_framework_mapper.nodes import (
    assess_categories,
    identify_gaps,
    map_functions,
    recommend,
    report,
    score_maturity,
)
from shieldops.agents.tracing import traced_node

_AGENT = "nist_framework_mapper"


def _check_error(state: NISTFrameworkMapperState) -> str:
    return "report" if state.error else "next"


def create_nist_framework_mapper_graph() -> StateGraph:
    """Build the NIST Framework Mapper LangGraph workflow."""
    graph = StateGraph(NISTFrameworkMapperState)

    graph.add_node(
        "map_functions",
        traced_node(f"{_AGENT}.map_functions", _AGENT)(map_functions),
    )
    graph.add_node(
        "assess_categories",
        traced_node(f"{_AGENT}.assess_categories", _AGENT)(assess_categories),
    )
    graph.add_node(
        "score_maturity",
        traced_node(f"{_AGENT}.score_maturity", _AGENT)(score_maturity),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("map_functions")

    graph.add_conditional_edges(
        "map_functions",
        _check_error,
        {"next": "assess_categories", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_categories",
        _check_error,
        {"next": "score_maturity", "report": "report"},
    )
    graph.add_conditional_edges(
        "score_maturity",
        _check_error,
        {"next": "identify_gaps", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_gaps",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
