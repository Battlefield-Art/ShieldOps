"""LangGraph workflow definition for the Threat
Landscape Analyzer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_landscape_analyzer.models import (
    ThreatLandscapeAnalyzerState,
)
from shieldops.agents.threat_landscape_analyzer.nodes import (
    analyze_trends,
    benchmark_posture,
    collect_intel,
    generate_report,
    generate_threat_brief,
    map_to_industry,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_landscape_analyzer"


def _should_brief(
    state: ThreatLandscapeAnalyzerState,
) -> str:
    """Route after benchmarking: generate brief if
    benchmark data exists, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.benchmark:
        return "generate_threat_brief"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Landscape Analyzer LangGraph
    workflow.

    Workflow:
        collect_intel -> analyze_trends
            -> map_to_industry -> benchmark_posture
            -> [benchmark? -> generate_threat_brief]
            -> generate_report -> END
    """
    graph = StateGraph(ThreatLandscapeAnalyzerState)

    graph.add_node(
        "collect_intel",
        traced_node(f"{_AGENT}.collect_intel", _AGENT)(collect_intel),
    )
    graph.add_node(
        "analyze_trends",
        traced_node(f"{_AGENT}.analyze_trends", _AGENT)(analyze_trends),
    )
    graph.add_node(
        "map_to_industry",
        traced_node(f"{_AGENT}.map_to_industry", _AGENT)(map_to_industry),
    )
    graph.add_node(
        "benchmark_posture",
        traced_node(f"{_AGENT}.benchmark_posture", _AGENT)(benchmark_posture),
    )
    graph.add_node(
        "generate_threat_brief",
        traced_node(f"{_AGENT}.generate_threat_brief", _AGENT)(generate_threat_brief),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_intel")
    graph.add_edge("collect_intel", "analyze_trends")
    graph.add_edge("analyze_trends", "map_to_industry")
    graph.add_edge("map_to_industry", "benchmark_posture")
    graph.add_conditional_edges(
        "benchmark_posture",
        _should_brief,
        {
            "generate_threat_brief": ("generate_threat_brief"),
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_threat_brief", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_threat_landscape_analyzer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Threat Landscape Analyzer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
