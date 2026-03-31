"""LangGraph workflow definition for the Network
Microsegmentation Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.network_microsegmentation.models import (
    NetworkMicrosegmentationState,
)
from shieldops.agents.network_microsegmentation.nodes import (
    analyze_flows,
    deploy_policies,
    generate_policies,
    generate_report,
    map_topology,
    validate_policies,
)
from shieldops.agents.tracing import traced_node

_AGENT = "network_microsegmentation"


def _should_deploy(
    state: NetworkMicrosegmentationState,
) -> str:
    """Route after validation: deploy if policies exist
    or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.policies_generated > 0:
        return "deploy_policies"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Network Microsegmentation LangGraph
    workflow.

    Workflow:
        map_topology -> analyze_flows
            -> generate_policies -> validate_policies
            -> [policies? -> deploy_policies]
            -> generate_report -> END
    """
    graph = StateGraph(NetworkMicrosegmentationState)

    graph.add_node(
        "map_topology",
        traced_node(f"{_AGENT}.map_topology", _AGENT)(map_topology),
    )
    graph.add_node(
        "analyze_flows",
        traced_node(f"{_AGENT}.analyze_flows", _AGENT)(analyze_flows),
    )
    graph.add_node(
        "generate_policies",
        traced_node(f"{_AGENT}.generate_policies", _AGENT)(generate_policies),
    )
    graph.add_node(
        "validate_policies",
        traced_node(f"{_AGENT}.validate_policies", _AGENT)(validate_policies),
    )
    graph.add_node(
        "deploy_policies",
        traced_node(f"{_AGENT}.deploy_policies", _AGENT)(deploy_policies),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("map_topology")
    graph.add_edge("map_topology", "analyze_flows")
    graph.add_edge("analyze_flows", "generate_policies")
    graph.add_edge("generate_policies", "validate_policies")
    graph.add_conditional_edges(
        "validate_policies",
        _should_deploy,
        {
            "deploy_policies": "deploy_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("deploy_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_network_microsegmentation_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Network Microsegmentation
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
