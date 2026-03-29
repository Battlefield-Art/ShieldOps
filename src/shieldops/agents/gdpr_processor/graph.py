"""GDPR Processor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import GDPRProcessorState
from .nodes import (
    check_breaches,
    check_consent,
    generate_report,
    intake_requests,
    map_data,
    process_requests,
)
from .tools import GDPRProcessorToolkit


def _route_after_intake(state: Any) -> str:
    """Route based on error presence."""
    raw = state if isinstance(state, dict) else state.model_dump()
    if raw.get("error"):
        return "generate_report"
    return "map_data"


def create_gdpr_processor_graph(
    toolkit: GDPRProcessorToolkit | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the GDPR Processor agent graph."""
    if toolkit is None:
        toolkit = GDPRProcessorToolkit()

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return state  # type: ignore[no-any-return]

    async def _intake(state: Any) -> dict[str, Any]:
        return await intake_requests(_to_dict(state), toolkit)

    async def _map_data(state: Any) -> dict[str, Any]:
        return await map_data(_to_dict(state), toolkit)

    async def _consent(state: Any) -> dict[str, Any]:
        return await check_consent(_to_dict(state), toolkit)

    async def _process(state: Any) -> dict[str, Any]:
        return await process_requests(_to_dict(state), toolkit)

    async def _breaches(state: Any) -> dict[str, Any]:
        return await check_breaches(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(GDPRProcessorState)
    graph.add_node("intake", _intake)
    graph.add_node("map_data", _map_data)
    graph.add_node("check_consent", _consent)
    graph.add_node("process_requests", _process)
    graph.add_node("check_breaches", _breaches)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("intake")
    graph.add_conditional_edges(
        "intake",
        _route_after_intake,
        {"map_data": "map_data", "generate_report": "generate_report"},
    )
    graph.add_edge("map_data", "check_consent")
    graph.add_edge("check_consent", "process_requests")
    graph.add_edge("process_requests", "check_breaches")
    graph.add_edge("check_breaches", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
