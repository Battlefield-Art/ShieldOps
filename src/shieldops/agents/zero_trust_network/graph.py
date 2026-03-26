"""Zero Trust Network Access — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ZeroTrustNetworkState
from .nodes import (
    assess_identity_trust,
    discover_access_points,
    enforce_policies,
    evaluate_device_posture,
    monitor_sessions,
    report,
)
from .tools import ZeroTrustNetworkToolkit


def _has_enforcements(state: Any) -> str:
    """Route based on whether enforcements exist."""
    if hasattr(state, "enforcements"):
        enforcements = state.enforcements
    else:
        enforcements = state.get("enforcements", [])
    if enforcements:
        return "monitor"
    return "report"


def build_graph(
    toolkit: ZeroTrustNetworkToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Zero Trust Network Access graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_access_points(_to_dict(state), toolkit)

    async def _trust(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_identity_trust(_to_dict(state), toolkit)

    async def _posture(
        state: Any,
    ) -> dict[str, Any]:
        return await evaluate_device_posture(_to_dict(state), toolkit)

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _monitor(
        state: Any,
    ) -> dict[str, Any]:
        return await monitor_sessions(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(ZeroTrustNetworkState)
    graph.add_node("discover_access_points", _discover)
    graph.add_node("assess_identity_trust", _trust)
    graph.add_node("evaluate_device_posture", _posture)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("monitor_sessions", _monitor)
    graph.add_node("report", _report)

    # Linear flow with conditional monitoring
    graph.set_entry_point("discover_access_points")
    graph.add_edge(
        "discover_access_points",
        "assess_identity_trust",
    )
    graph.add_edge(
        "assess_identity_trust",
        "evaluate_device_posture",
    )
    graph.add_edge(
        "evaluate_device_posture",
        "enforce_policies",
    )
    graph.add_conditional_edges(
        "enforce_policies",
        _has_enforcements,
        {
            "monitor": "monitor_sessions",
            "report": "report",
        },
    )
    graph.add_edge("monitor_sessions", "report")
    graph.add_edge("report", END)

    return graph


def create_zero_trust_network_graph(
    policy_engine: Any | None = None,
    identity_store: Any | None = None,
    alert_sink: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the ZTNA graph with dependencies."""
    toolkit = ZeroTrustNetworkToolkit(
        policy_engine=policy_engine,
        identity_store=identity_store,
        alert_sink=alert_sink,
    )
    return build_graph(toolkit)
