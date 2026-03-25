"""Service Account Tracker — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ServiceAccountTrackerState
from .nodes import (
    analyze_usage,
    classify_risk,
    detect_anomalies,
    discover,
    generate_report,
    remediate,
)
from .tools import ServiceAccountTrackerToolkit


def _has_anomalies(state: Any) -> str:
    """Route based on whether anomalies or sharing detections were found."""
    if hasattr(state, "usage_anomalies"):
        anomalies = state.usage_anomalies
        sharing = state.sharing_detections
    else:
        anomalies = state.get("usage_anomalies", [])
        sharing = state.get("sharing_detections", [])
    if anomalies or sharing:
        return "remediate"
    return "report"


def build_graph(
    toolkit: ServiceAccountTrackerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Service Account Tracker graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover(_to_dict(state), toolkit)

    async def _analyze_usage(state: Any) -> dict[str, Any]:
        return await analyze_usage(_to_dict(state), toolkit)

    async def _detect_anomalies(state: Any) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _classify_risk(state: Any) -> dict[str, Any]:
        return await classify_risk(_to_dict(state), toolkit)

    async def _remediate(state: Any) -> dict[str, Any]:
        return await remediate(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ServiceAccountTrackerState)
    graph.add_node("discover", _discover)
    graph.add_node("analyze_usage", _analyze_usage)
    graph.add_node("detect_anomalies", _detect_anomalies)
    graph.add_node("classify_risk", _classify_risk)
    graph.add_node("remediate", _remediate)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover")
    graph.add_edge("discover", "analyze_usage")
    graph.add_edge("analyze_usage", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify_risk")
    graph.add_conditional_edges(
        "classify_risk",
        _has_anomalies,
        {"remediate": "remediate", "report": "generate_report"},
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_service_account_tracker_graph(
    cloud_connectors: dict[str, Any] | None = None,
    policy_engine: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Service Account Tracker graph with dependencies."""
    toolkit = ServiceAccountTrackerToolkit(
        cloud_connectors=cloud_connectors,
        policy_engine=policy_engine,
        repository=repository,
    )
    return build_graph(toolkit)
