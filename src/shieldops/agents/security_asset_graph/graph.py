"""LangGraph workflow definition for the Security Asset
Graph Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_asset_graph.models import (
    SecurityAssetGraphState,
)
from shieldops.agents.security_asset_graph.nodes import (
    analyze_impact,
    discover_assets,
    generate_report,
    identify_critical_paths,
    map_dependencies,
    score_risk,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_asset_graph"


def _should_score(
    state: SecurityAssetGraphState,
) -> str:
    """Route after critical path identification: score
    risk if paths found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.critical_paths:
        return "score_risk"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Asset Graph LangGraph workflow.

    Workflow:
        discover_assets -> map_dependencies
            -> analyze_impact -> identify_critical_paths
            -> [paths? -> score_risk]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityAssetGraphState)

    graph.add_node(
        "discover_assets",
        traced_node(f"{_AGENT}.discover_assets", _AGENT)(discover_assets),
    )
    graph.add_node(
        "map_dependencies",
        traced_node(f"{_AGENT}.map_dependencies", _AGENT)(map_dependencies),
    )
    graph.add_node(
        "analyze_impact",
        traced_node(f"{_AGENT}.analyze_impact", _AGENT)(analyze_impact),
    )
    graph.add_node(
        "identify_critical_paths",
        traced_node(f"{_AGENT}.identify_critical_paths", _AGENT)(identify_critical_paths),
    )
    graph.add_node(
        "score_risk",
        traced_node(f"{_AGENT}.score_risk", _AGENT)(score_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_assets")
    graph.add_edge("discover_assets", "map_dependencies")
    graph.add_edge("map_dependencies", "analyze_impact")
    graph.add_edge("analyze_impact", "identify_critical_paths")
    graph.add_conditional_edges(
        "identify_critical_paths",
        _should_score,
        {
            "score_risk": "score_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("score_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_asset_graph_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Asset Graph
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
