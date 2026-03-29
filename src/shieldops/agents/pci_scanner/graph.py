"""PCI Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PCIScannerState
from .nodes import (
    check_requirements,
    complete_saq,
    generate_report,
    map_cde,
    run_asv_scan,
)
from .tools import PCIScannerToolkit


def _route_after_cde(state: Any) -> str:
    """Route based on error presence."""
    raw = state if isinstance(state, dict) else state.model_dump()
    if raw.get("error"):
        return "generate_report"
    return "check_requirements"


def create_pci_scanner_graph(
    toolkit: PCIScannerToolkit | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the PCI Scanner agent graph."""
    if toolkit is None:
        toolkit = PCIScannerToolkit()

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return state  # type: ignore[no-any-return]

    async def _map_cde(state: Any) -> dict[str, Any]:
        return await map_cde(_to_dict(state), toolkit)

    async def _check(state: Any) -> dict[str, Any]:
        return await check_requirements(_to_dict(state), toolkit)

    async def _asv(state: Any) -> dict[str, Any]:
        return await run_asv_scan(_to_dict(state), toolkit)

    async def _saq(state: Any) -> dict[str, Any]:
        return await complete_saq(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(PCIScannerState)
    graph.add_node("map_cde", _map_cde)
    graph.add_node("check_requirements", _check)
    graph.add_node("asv_scan", _asv)
    graph.add_node("complete_saq", _saq)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("map_cde")
    graph.add_conditional_edges(
        "map_cde",
        _route_after_cde,
        {
            "check_requirements": "check_requirements",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("check_requirements", "asv_scan")
    graph.add_edge("asv_scan", "complete_saq")
    graph.add_edge("complete_saq", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
