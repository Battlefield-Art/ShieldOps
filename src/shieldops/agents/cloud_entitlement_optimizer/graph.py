"""LangGraph workflow for the Cloud Entitlement Optimizer."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_entitlement_optimizer.models import (
    CloudEntitlementOptimizerState,
)
from shieldops.agents.cloud_entitlement_optimizer.nodes import (
    analyze_usage,
    calculate_risk,
    generate_report,
    identify_excess,
    inventory_entitlements,
    recommend_changes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_entitlement_optimizer"


def _should_identify(
    state: CloudEntitlementOptimizerState,
) -> str:
    if state.error:
        return "generate_report"
    if state.usage_analyses:
        return "identify_excess"
    return "generate_report"


def _should_recommend(
    state: CloudEntitlementOptimizerState,
) -> str:
    if state.risk_assessments:
        return "recommend_changes"
    return "generate_report"


def create_cloud_entitlement_optimizer_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Entitlement Optimizer LangGraph.

    Workflow:
        inventory_entitlements -> analyze_usage
          -> [has_analyses?] -> identify_excess -> calculate_risk
          -> [has_risks?] -> recommend_changes -> generate_report
    """
    graph = StateGraph(CloudEntitlementOptimizerState)

    graph.add_node(
        "inventory_entitlements",
        traced_node(
            f"{_AGENT}.inventory_entitlements",
            _AGENT,
        )(inventory_entitlements),
    )
    graph.add_node(
        "analyze_usage",
        traced_node(f"{_AGENT}.analyze_usage", _AGENT)(
            analyze_usage,
        ),
    )
    graph.add_node(
        "identify_excess",
        traced_node(f"{_AGENT}.identify_excess", _AGENT)(
            identify_excess,
        ),
    )
    graph.add_node(
        "calculate_risk",
        traced_node(f"{_AGENT}.calculate_risk", _AGENT)(
            calculate_risk,
        ),
    )
    graph.add_node(
        "recommend_changes",
        traced_node(f"{_AGENT}.recommend_changes", _AGENT)(
            recommend_changes,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("inventory_entitlements")
    graph.add_edge("inventory_entitlements", "analyze_usage")
    graph.add_conditional_edges(
        "analyze_usage",
        _should_identify,
        {
            "identify_excess": "identify_excess",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("identify_excess", "calculate_risk")
    graph.add_conditional_edges(
        "calculate_risk",
        _should_recommend,
        {
            "recommend_changes": "recommend_changes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_changes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
