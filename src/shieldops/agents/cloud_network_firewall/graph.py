"""Cloud Network Firewall Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudNetworkFirewallState
from .nodes import (
    analyze_coverage,
    collect_rules,
    detect_overpermissive,
    find_shadow_rules,
    generate_report,
    optimize_rules,
)
from .tools import CloudNetworkFirewallToolkit


def _has_findings(state: Any) -> str:
    """Route to optimize if findings exist, else report."""
    if isinstance(state, dict):
        op = state.get("overpermissive_rules", [])
        sh = state.get("shadow_rules", [])
    else:
        op = getattr(state, "overpermissive_rules", [])
        sh = getattr(state, "shadow_rules", [])

    if op or sh:
        return "optimize_rules"
    return "generate_report"


def build_graph(
    toolkit: CloudNetworkFirewallToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Network Firewall agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_rules(_to_dict(state), toolkit)

    async def _coverage(state: Any) -> dict[str, Any]:
        return await analyze_coverage(_to_dict(state), toolkit)

    async def _overperm(state: Any) -> dict[str, Any]:
        return await detect_overpermissive(_to_dict(state), toolkit)

    async def _shadow(state: Any) -> dict[str, Any]:
        return await find_shadow_rules(_to_dict(state), toolkit)

    async def _optimize(state: Any) -> dict[str, Any]:
        return await optimize_rules(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CloudNetworkFirewallState)

    # Add nodes
    graph.add_node("collect_rules", _collect)
    graph.add_node("analyze_coverage", _coverage)
    graph.add_node("detect_overpermissive", _overperm)
    graph.add_node("find_shadow_rules", _shadow)
    graph.add_node("optimize_rules", _optimize)
    graph.add_node("generate_report", _report)

    # Linear flow: collect -> coverage -> overperm -> shadow
    graph.set_entry_point("collect_rules")
    graph.add_edge("collect_rules", "analyze_coverage")
    graph.add_edge("analyze_coverage", "detect_overpermissive")
    graph.add_edge("detect_overpermissive", "find_shadow_rules")

    # Conditional: if findings exist -> optimize -> report
    graph.add_conditional_edges(
        "find_shadow_rules",
        _has_findings,
        {
            "optimize_rules": "optimize_rules",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("optimize_rules", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_network_firewall_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Network Firewall agent graph."""
    toolkit = CloudNetworkFirewallToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
