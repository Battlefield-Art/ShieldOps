"""Dependency Graph Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.dependency_graph_analyzer.models import DependencyGraphAnalyzerState
from shieldops.agents.dependency_graph_analyzer.nodes import (
    analyze_depth,
    build_graph,
    detect_cycles,
    find_bottlenecks,
    report,
    score,
)
from shieldops.agents.tracing import traced_node

_AGENT = "dependency_graph_analyzer"


def _check_error(state: DependencyGraphAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_dependency_graph_analyzer_graph() -> StateGraph:
    """Build the Dependency Graph Analyzer workflow."""
    graph = StateGraph(DependencyGraphAnalyzerState)

    graph.add_node(
        "build_graph",
        traced_node(f"{_AGENT}.build_graph", _AGENT)(build_graph),
    )
    graph.add_node(
        "analyze_depth",
        traced_node(f"{_AGENT}.analyze_depth", _AGENT)(analyze_depth),
    )
    graph.add_node(
        "find_bottlenecks",
        traced_node(f"{_AGENT}.find_bottlenecks", _AGENT)(find_bottlenecks),
    )
    graph.add_node(
        "detect_cycles",
        traced_node(f"{_AGENT}.detect_cycles", _AGENT)(detect_cycles),
    )
    graph.add_node(
        "score",
        traced_node(f"{_AGENT}.score", _AGENT)(score),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("build_graph")

    graph.add_conditional_edges(
        "build_graph",
        _check_error,
        {"next": "analyze_depth", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_depth",
        _check_error,
        {"next": "find_bottlenecks", "report": "report"},
    )
    graph.add_conditional_edges(
        "find_bottlenecks",
        _check_error,
        {"next": "detect_cycles", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_cycles",
        _check_error,
        {"next": "score", "report": "report"},
    )
    graph.add_edge("score", "report")
    graph.add_edge("report", END)

    return graph
