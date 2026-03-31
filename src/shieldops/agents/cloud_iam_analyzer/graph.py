"""LangGraph workflow definition for the Cloud IAM
Analyzer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_iam_analyzer.models import (
    CloudIAMAnalyzerState,
)
from shieldops.agents.cloud_iam_analyzer.nodes import (
    analyze_permissions,
    collect_policies,
    compare_clouds,
    detect_risks,
    generate_report,
    optimize,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_iam_analyzer"


def _should_optimize(
    state: CloudIAMAnalyzerState,
) -> str:
    """Route after comparison: optimize if risks exist
    or skip to report on error."""
    if state.error:
        return "generate_report"
    if state.risk_findings:
        return "optimize"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud IAM Analyzer LangGraph workflow.

    Workflow:
        collect_policies -> analyze_permissions
            -> detect_risks -> compare_clouds
            -> [risks? -> optimize]
            -> generate_report -> END
    """
    graph = StateGraph(CloudIAMAnalyzerState)

    graph.add_node(
        "collect_policies",
        traced_node(f"{_AGENT}.collect_policies", _AGENT)(collect_policies),
    )
    graph.add_node(
        "analyze_permissions",
        traced_node(f"{_AGENT}.analyze_permissions", _AGENT)(analyze_permissions),
    )
    graph.add_node(
        "detect_risks",
        traced_node(f"{_AGENT}.detect_risks", _AGENT)(detect_risks),
    )
    graph.add_node(
        "compare_clouds",
        traced_node(f"{_AGENT}.compare_clouds", _AGENT)(compare_clouds),
    )
    graph.add_node(
        "optimize",
        traced_node(f"{_AGENT}.optimize", _AGENT)(optimize),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_policies")
    graph.add_edge("collect_policies", "analyze_permissions")
    graph.add_edge("analyze_permissions", "detect_risks")
    graph.add_edge("detect_risks", "compare_clouds")
    graph.add_conditional_edges(
        "compare_clouds",
        _should_optimize,
        {
            "optimize": "optimize",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("optimize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_iam_analyzer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud IAM Analyzer graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
