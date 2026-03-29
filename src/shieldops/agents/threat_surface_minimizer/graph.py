"""Threat Surface Minimizer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_surface_minimizer.models import ThreatSurfaceMinimizerState
from shieldops.agents.threat_surface_minimizer.nodes import (
    discover_surface,
    map_exposure,
    prioritize_risks,
    recommend_reduction,
    report,
    validate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_surface_minimizer"


def _check_error(state: ThreatSurfaceMinimizerState) -> str:
    return "report" if state.error else "next"


def create_threat_surface_minimizer_graph() -> StateGraph:
    """Build the Threat Surface Minimizer workflow."""
    graph = StateGraph(ThreatSurfaceMinimizerState)

    graph.add_node(
        "discover_surface",
        traced_node(f"{_AGENT}.discover_surface", _AGENT)(discover_surface),
    )
    graph.add_node(
        "map_exposure",
        traced_node(f"{_AGENT}.map_exposure", _AGENT)(map_exposure),
    )
    graph.add_node(
        "prioritize_risks",
        traced_node(f"{_AGENT}.prioritize_risks", _AGENT)(prioritize_risks),
    )
    graph.add_node(
        "recommend_reduction",
        traced_node(f"{_AGENT}.recommend_reduction", _AGENT)(recommend_reduction),
    )
    graph.add_node(
        "validate",
        traced_node(f"{_AGENT}.validate", _AGENT)(validate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_surface")

    graph.add_conditional_edges(
        "discover_surface",
        _check_error,
        {"next": "map_exposure", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_exposure",
        _check_error,
        {"next": "prioritize_risks", "report": "report"},
    )
    graph.add_conditional_edges(
        "prioritize_risks",
        _check_error,
        {"next": "recommend_reduction", "report": "report"},
    )
    graph.add_conditional_edges(
        "recommend_reduction",
        _check_error,
        {"next": "validate", "report": "report"},
    )
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph
