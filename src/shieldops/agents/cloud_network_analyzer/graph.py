"""LangGraph workflow definition for the Cloud Network
Analyzer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_network_analyzer.models import (
    CloudNetworkAnalyzerState,
)
from shieldops.agents.cloud_network_analyzer.nodes import (
    analyze_routes,
    check_segmentation,
    detect_exposure,
    discover_topology,
    generate_report,
    recommend,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_network_analyzer"


def _should_recommend(
    state: CloudNetworkAnalyzerState,
) -> str:
    """Route after exposure detection: recommend if
    findings exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.exposure_count > 0:
        return "recommend"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Network Analyzer LangGraph
    workflow.

    Workflow:
        discover_topology -> analyze_routes
            -> check_segmentation -> detect_exposure
            -> [findings? -> recommend]
            -> generate_report -> END
    """
    graph = StateGraph(CloudNetworkAnalyzerState)

    graph.add_node(
        "discover_topology",
        traced_node(f"{_AGENT}.discover_topology", _AGENT)(discover_topology),
    )
    graph.add_node(
        "analyze_routes",
        traced_node(f"{_AGENT}.analyze_routes", _AGENT)(analyze_routes),
    )
    graph.add_node(
        "check_segmentation",
        traced_node(f"{_AGENT}.check_segmentation", _AGENT)(check_segmentation),
    )
    graph.add_node(
        "detect_exposure",
        traced_node(f"{_AGENT}.detect_exposure", _AGENT)(detect_exposure),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_topology")
    graph.add_edge("discover_topology", "analyze_routes")
    graph.add_edge("analyze_routes", "check_segmentation")
    graph.add_edge("check_segmentation", "detect_exposure")
    graph.add_conditional_edges(
        "detect_exposure",
        _should_recommend,
        {
            "recommend": "recommend",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_network_analyzer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Network Analyzer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
