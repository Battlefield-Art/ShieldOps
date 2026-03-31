"""LangGraph workflow definition for the Cloud Permission
Optimizer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_permission_optimizer.models import (
    CloudPermissionOptimizerState,
)
from shieldops.agents.cloud_permission_optimizer.nodes import (
    analyze_usage,
    calculate_least_privilege,
    collect_permissions,
    detect_excess,
    generate_report,
    recommend_changes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_permission_optimizer"


def _should_recommend(
    state: CloudPermissionOptimizerState,
) -> str:
    """Route after least-privilege: recommend if policies
    exist or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.least_privilege_policies:
        return "recommend_changes"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Permission Optimizer LangGraph
    workflow.

    Workflow:
        collect_permissions -> analyze_usage
            -> detect_excess -> calculate_least_privilege
            -> [policies? -> recommend_changes]
            -> generate_report -> END
    """
    graph = StateGraph(CloudPermissionOptimizerState)

    graph.add_node(
        "collect_permissions",
        traced_node(f"{_AGENT}.collect_permissions", _AGENT)(collect_permissions),
    )
    graph.add_node(
        "analyze_usage",
        traced_node(f"{_AGENT}.analyze_usage", _AGENT)(analyze_usage),
    )
    graph.add_node(
        "detect_excess",
        traced_node(f"{_AGENT}.detect_excess", _AGENT)(detect_excess),
    )
    graph.add_node(
        "calculate_least_privilege",
        traced_node(f"{_AGENT}.calculate_least_privilege", _AGENT)(calculate_least_privilege),
    )
    graph.add_node(
        "recommend_changes",
        traced_node(f"{_AGENT}.recommend_changes", _AGENT)(recommend_changes),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_permissions")
    graph.add_edge("collect_permissions", "analyze_usage")
    graph.add_edge("analyze_usage", "detect_excess")
    graph.add_edge("detect_excess", "calculate_least_privilege")
    graph.add_conditional_edges(
        "calculate_least_privilege",
        _should_recommend,
        {
            "recommend_changes": "recommend_changes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_changes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_permission_optimizer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Permission Optimizer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
