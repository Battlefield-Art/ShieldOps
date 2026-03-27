"""Endpoint DLP Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import EndpointDLPState
from .nodes import (
    classify_sensitivity,
    detect_data_movement,
    enforce_policies,
    investigate_violations,
    monitor_endpoints,
    report,
)
from .tools import EndpointDLPToolkit


def build_graph(
    toolkit: EndpointDLPToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Endpoint DLP agent graph.

    Flow:
        monitor_endpoints -> detect_data_movement
        -> classify_sensitivity -> enforce_policies
        -> investigate_violations -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _monitor(
        state: Any,
    ) -> dict[str, Any]:
        return await monitor_endpoints(_to_dict(state), toolkit)

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_data_movement(_to_dict(state), toolkit)

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_sensitivity(_to_dict(state), toolkit)

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _investigate(
        state: Any,
    ) -> dict[str, Any]:
        return await investigate_violations(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(EndpointDLPState)
    graph.add_node("monitor_endpoints", _monitor)
    graph.add_node("detect_data_movement", _detect)
    graph.add_node("classify_sensitivity", _classify)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("investigate_violations", _investigate)
    graph.add_node("report", _report)

    graph.set_entry_point("monitor_endpoints")
    graph.add_edge(
        "monitor_endpoints",
        "detect_data_movement",
    )
    graph.add_edge(
        "detect_data_movement",
        "classify_sensitivity",
    )
    graph.add_edge(
        "classify_sensitivity",
        "enforce_policies",
    )
    graph.add_edge(
        "enforce_policies",
        "investigate_violations",
    )
    graph.add_edge("investigate_violations", "report")
    graph.add_edge("report", END)

    return graph


def create_endpoint_dlp_graph(
    edr_client: Any | None = None,
    dlp_engine: Any | None = None,
    siem_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint DLP graph."""
    toolkit = EndpointDLPToolkit(
        edr_client=edr_client,
        dlp_engine=dlp_engine,
        siem_client=siem_client,
    )
    return build_graph(toolkit)
