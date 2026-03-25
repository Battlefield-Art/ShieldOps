"""Lateral Movement Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import LateralMovementState
from .nodes import (
    analyze_paths,
    assess_blast_radius,
    collect_signals,
    detect_pivots,
    generate_report,
    respond,
)
from .tools import LateralMovementToolkit


def _has_movement_paths(state: Any) -> str:
    """Route based on whether movement paths were detected."""
    if hasattr(state, "movement_paths"):
        paths = state.movement_paths
    else:
        paths = state.get("movement_paths", [])
    if paths:
        return "respond"
    return "report"


def build_graph(toolkit: LateralMovementToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Lateral Movement Detector graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect_signals(state: Any) -> dict[str, Any]:
        return await collect_signals(_to_dict(state), toolkit)

    async def _analyze_paths(state: Any) -> dict[str, Any]:
        return await analyze_paths(_to_dict(state), toolkit)

    async def _detect_pivots(state: Any) -> dict[str, Any]:
        return await detect_pivots(_to_dict(state), toolkit)

    async def _assess_blast_radius(state: Any) -> dict[str, Any]:
        return await assess_blast_radius(_to_dict(state), toolkit)

    async def _respond(state: Any) -> dict[str, Any]:
        return await respond(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(LateralMovementState)
    graph.add_node("collect_signals", _collect_signals)
    graph.add_node("analyze_paths", _analyze_paths)
    graph.add_node("detect_pivots", _detect_pivots)
    graph.add_node("assess_blast_radius", _assess_blast_radius)
    graph.add_node("respond", _respond)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_signals")
    graph.add_edge("collect_signals", "analyze_paths")
    graph.add_edge("analyze_paths", "detect_pivots")
    graph.add_edge("detect_pivots", "assess_blast_radius")
    graph.add_conditional_edges(
        "assess_blast_radius",
        _has_movement_paths,
        {"respond": "respond", "report": "report"},
    )
    graph.add_edge("respond", "report")
    graph.add_edge("report", END)

    return graph


def create_lateral_movement_graph(
    identity_store: Any | None = None,
    cloud_connectors: dict[str, Any] | None = None,
    response_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Lateral Movement Detector graph with dependencies."""
    toolkit = LateralMovementToolkit(
        identity_store=identity_store,
        cloud_connectors=cloud_connectors,
        response_engine=response_engine,
    )
    return build_graph(toolkit)
