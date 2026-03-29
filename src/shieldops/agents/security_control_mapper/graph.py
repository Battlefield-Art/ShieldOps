"""Security Control Mapper Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_control_mapper.models import SecurityControlMapperState
from shieldops.agents.security_control_mapper.nodes import (
    collect_controls,
    cross_reference,
    identify_gaps,
    map_frameworks,
    report,
    score,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_control_mapper"


def _check_error(state: SecurityControlMapperState) -> str:
    return "report" if state.error else "next"


def create_security_control_mapper_graph() -> StateGraph:
    """Build the Security Control Mapper workflow."""
    graph = StateGraph(SecurityControlMapperState)

    graph.add_node(
        "collect_controls",
        traced_node(f"{_AGENT}.collect_controls", _AGENT)(collect_controls),
    )
    graph.add_node(
        "map_frameworks",
        traced_node(f"{_AGENT}.map_frameworks", _AGENT)(map_frameworks),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "cross_reference",
        traced_node(f"{_AGENT}.cross_reference", _AGENT)(cross_reference),
    )
    graph.add_node(
        "score",
        traced_node(f"{_AGENT}.score", _AGENT)(score),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_controls")

    graph.add_conditional_edges(
        "collect_controls",
        _check_error,
        {"next": "map_frameworks", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_frameworks",
        _check_error,
        {"next": "identify_gaps", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_gaps",
        _check_error,
        {"next": "cross_reference", "report": "report"},
    )
    graph.add_conditional_edges(
        "cross_reference",
        _check_error,
        {"next": "score", "report": "report"},
    )
    graph.add_edge("score", "report")
    graph.add_edge("report", END)

    return graph
