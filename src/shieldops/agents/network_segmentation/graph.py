"""Network Segmentation Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import NetworkSegmentationState
from .nodes import (
    assess_risk,
    detect_violations,
    discover_zones,
    enforce_policies,
    map_traffic,
    report,
)
from .tools import NetworkSegmentationToolkit


def _has_violations(state: Any) -> str:
    """Route based on whether violations were found."""
    violations = state.violations if hasattr(state, "violations") else state.get("violations", [])
    if violations:
        return "enforce"
    return "report"


def build_graph(
    toolkit: NetworkSegmentationToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Network Segmentation graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_zones(_to_dict(state), toolkit)

    async def _map(state: Any) -> dict[str, Any]:
        return await map_traffic(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_violations(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(NetworkSegmentationState)
    graph.add_node("discover_zones", _discover)
    graph.add_node("map_traffic", _map)
    graph.add_node("detect_violations", _detect)
    graph.add_node("assess_risk", _assess)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_zones")
    graph.add_edge("discover_zones", "map_traffic")
    graph.add_edge("map_traffic", "detect_violations")
    graph.add_edge("detect_violations", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _has_violations,
        {"enforce": "enforce_policies", "report": "report"},
    )
    graph.add_edge("enforce_policies", "report")
    graph.add_edge("report", END)

    return graph


def create_network_segmentation_graph(
    network_client: Any | None = None,
    firewall_client: Any | None = None,
    policy_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Network Segmentation graph with dependencies."""
    toolkit = NetworkSegmentationToolkit(
        network_client=network_client,
        firewall_client=firewall_client,
        policy_engine=policy_engine,
    )
    return build_graph(toolkit)
