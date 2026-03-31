"""LangGraph workflow definition for the Cloud Entitlement
Manager Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_entitlement_manager.models import (
    CloudEntitlementManagerState,
)
from shieldops.agents.cloud_entitlement_manager.nodes import (
    analyze_permissions,
    assess_risk,
    detect_excess,
    discover_identities,
    generate_report,
    recommend_least_privilege,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_entitlement_manager"


def _should_recommend(
    state: CloudEntitlementManagerState,
) -> str:
    """Route after risk assessment: recommend if excess
    found or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.excess_count > 0:
        return "recommend_least_privilege"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Entitlement Manager LangGraph
    workflow.

    Workflow:
        discover_identities -> analyze_permissions
            -> detect_excess -> assess_risk
            -> [excess? -> recommend_least_privilege]
            -> generate_report -> END
    """
    graph = StateGraph(CloudEntitlementManagerState)

    graph.add_node(
        "discover_identities",
        traced_node(f"{_AGENT}.discover_identities", _AGENT)(discover_identities),
    )
    graph.add_node(
        "analyze_permissions",
        traced_node(f"{_AGENT}.analyze_permissions", _AGENT)(analyze_permissions),
    )
    graph.add_node(
        "detect_excess",
        traced_node(f"{_AGENT}.detect_excess", _AGENT)(detect_excess),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "recommend_least_privilege",
        traced_node(f"{_AGENT}.recommend_least_privilege", _AGENT)(recommend_least_privilege),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_identities")
    graph.add_edge("discover_identities", "analyze_permissions")
    graph.add_edge("analyze_permissions", "detect_excess")
    graph.add_edge("detect_excess", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _should_recommend,
        {
            "recommend_least_privilege": ("recommend_least_privilege"),
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_least_privilege", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_entitlement_manager_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Entitlement Manager
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
