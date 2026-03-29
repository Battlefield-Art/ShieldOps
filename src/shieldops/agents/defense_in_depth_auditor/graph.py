"""Defense In Depth Auditor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.defense_in_depth_auditor.models import DefenseInDepthAuditorState
from shieldops.agents.defense_in_depth_auditor.nodes import (
    assess_controls,
    identify_gaps,
    map_layers,
    recommend,
    report,
    test_resilience,
)
from shieldops.agents.tracing import traced_node

_AGENT = "defense_in_depth_auditor"


def _check_error(state: DefenseInDepthAuditorState) -> str:
    return "report" if state.error else "next"


def create_defense_in_depth_auditor_graph() -> StateGraph:
    """Build the Defense In Depth Auditor workflow."""
    graph = StateGraph(DefenseInDepthAuditorState)

    graph.add_node(
        "map_layers",
        traced_node(f"{_AGENT}.map_layers", _AGENT)(map_layers),
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
        "test_resilience",
        traced_node(f"{_AGENT}.test_resilience", _AGENT)(test_resilience),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("map_layers")

    graph.add_conditional_edges(
        "map_layers",
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
        {"next": "test_resilience", "report": "report"},
    )
    graph.add_conditional_edges(
        "test_resilience",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
