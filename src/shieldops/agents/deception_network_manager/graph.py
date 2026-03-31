"""LangGraph workflow definition for the Deception Network
Manager Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.deception_network_manager.models import (
    DeceptionNetworkManagerState,
)
from shieldops.agents.deception_network_manager.nodes import (
    analyze_behavior,
    classify_attacker,
    deploy_decoys,
    generate_intel,
    generate_report,
    monitor_interactions,
)
from shieldops.agents.tracing import traced_node

_AGENT = "deception_network_manager"


def _should_classify(
    state: DeceptionNetworkManagerState,
) -> str:
    """Route after behavior analysis: classify if behaviors
    found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.high_risk_count > 0 or len(state.behaviors) > 0:
        return "classify_attacker"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Deception Network Manager LangGraph
    workflow.

    Workflow:
        deploy_decoys -> monitor_interactions
            -> analyze_behavior
            -> [behaviors? -> classify_attacker
                -> generate_intel]
            -> generate_report -> END
    """
    graph = StateGraph(DeceptionNetworkManagerState)

    graph.add_node(
        "deploy_decoys",
        traced_node(f"{_AGENT}.deploy_decoys", _AGENT)(deploy_decoys),
    )
    graph.add_node(
        "monitor_interactions",
        traced_node(f"{_AGENT}.monitor_interactions", _AGENT)(monitor_interactions),
    )
    graph.add_node(
        "analyze_behavior",
        traced_node(f"{_AGENT}.analyze_behavior", _AGENT)(analyze_behavior),
    )
    graph.add_node(
        "classify_attacker",
        traced_node(f"{_AGENT}.classify_attacker", _AGENT)(classify_attacker),
    )
    graph.add_node(
        "generate_intel",
        traced_node(f"{_AGENT}.generate_intel", _AGENT)(generate_intel),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("deploy_decoys")
    graph.add_edge("deploy_decoys", "monitor_interactions")
    graph.add_edge("monitor_interactions", "analyze_behavior")
    graph.add_conditional_edges(
        "analyze_behavior",
        _should_classify,
        {
            "classify_attacker": "classify_attacker",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("classify_attacker", "generate_intel")
    graph.add_edge("generate_intel", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_deception_network_manager_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Deception Network Manager
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
