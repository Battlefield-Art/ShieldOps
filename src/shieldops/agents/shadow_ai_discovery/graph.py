"""Shadow AI Discovery Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import GovernanceStatus, ShadowAIDiscoveryState
from .nodes import (
    analyze_traffic,
    classify_risk,
    generate_report,
    identify_agents,
    recommend_governance,
    scan_network,
)
from .tools import ShadowAIDiscoveryToolkit


def _needs_governance(state: Any) -> str:
    """Route based on whether unmanaged/rogue/shadow assets were found."""
    if hasattr(state, "discovered_assets"):
        assets = state.discovered_assets
    else:
        assets = state.get("discovered_assets", [])

    ungoverned_statuses = {
        GovernanceStatus.UNMANAGED.value,
        GovernanceStatus.SHADOW.value,
        GovernanceStatus.ROGUE.value,
    }
    for asset in assets:
        status = asset.get("governance_status", "") if isinstance(asset, dict) else ""
        if status in ungoverned_statuses:
            return "recommend_governance"

    return "generate_report"


def build_graph(
    toolkit: ShadowAIDiscoveryToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Shadow AI Discovery graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan_network(state: Any) -> dict[str, Any]:
        return await scan_network(_to_dict(state), toolkit)

    async def _analyze_traffic(state: Any) -> dict[str, Any]:
        return await analyze_traffic(_to_dict(state), toolkit)

    async def _identify_agents(state: Any) -> dict[str, Any]:
        return await identify_agents(_to_dict(state), toolkit)

    async def _classify_risk(state: Any) -> dict[str, Any]:
        return await classify_risk(_to_dict(state), toolkit)

    async def _recommend_governance(state: Any) -> dict[str, Any]:
        return await recommend_governance(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ShadowAIDiscoveryState)
    graph.add_node("scan_network", _scan_network)
    graph.add_node("analyze_traffic", _analyze_traffic)
    graph.add_node("identify_agents", _identify_agents)
    graph.add_node("classify_risk", _classify_risk)
    graph.add_node("recommend_governance", _recommend_governance)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("scan_network")
    graph.add_edge("scan_network", "analyze_traffic")
    graph.add_edge("analyze_traffic", "identify_agents")
    graph.add_edge("identify_agents", "classify_risk")
    graph.add_conditional_edges(
        "classify_risk",
        _needs_governance,
        {
            "recommend_governance": "recommend_governance",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_governance", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_shadow_ai_discovery_graph(
    network_scanner: Any | None = None,
    asset_registry: Any | None = None,
    policy_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory function to create a configured Shadow AI Discovery graph."""
    toolkit = ShadowAIDiscoveryToolkit(
        network_scanner=network_scanner,
        asset_registry=asset_registry,
        policy_engine=policy_engine,
    )
    return build_graph(toolkit)
