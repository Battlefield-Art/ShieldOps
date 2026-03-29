"""Threat Landscape Mapper Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_landscape_mapper.models import ThreatLandscapeMapperState
from shieldops.agents.threat_landscape_mapper.nodes import (
    assess_relevance,
    collect_intel,
    identify_trends,
    map_actors,
    prioritize,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_landscape_mapper"


def _check_error(state: ThreatLandscapeMapperState) -> str:
    return "report" if state.error else "next"


def create_threat_landscape_mapper_graph() -> StateGraph:
    """Build the Threat Landscape Mapper workflow."""
    graph = StateGraph(ThreatLandscapeMapperState)

    graph.add_node(
        "collect_intel",
        traced_node(f"{_AGENT}.collect_intel", _AGENT)(collect_intel),
    )
    graph.add_node(
        "map_actors",
        traced_node(f"{_AGENT}.map_actors", _AGENT)(map_actors),
    )
    graph.add_node(
        "identify_trends",
        traced_node(f"{_AGENT}.identify_trends", _AGENT)(identify_trends),
    )
    graph.add_node(
        "assess_relevance",
        traced_node(f"{_AGENT}.assess_relevance", _AGENT)(assess_relevance),
    )
    graph.add_node(
        "prioritize",
        traced_node(f"{_AGENT}.prioritize", _AGENT)(prioritize),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_intel")

    graph.add_conditional_edges(
        "collect_intel",
        _check_error,
        {"next": "map_actors", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_actors",
        _check_error,
        {"next": "identify_trends", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_trends",
        _check_error,
        {"next": "assess_relevance", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_relevance",
        _check_error,
        {"next": "prioritize", "report": "report"},
    )
    graph.add_edge("prioritize", "report")
    graph.add_edge("report", END)

    return graph
