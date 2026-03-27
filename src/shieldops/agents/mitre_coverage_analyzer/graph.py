"""MITRE Coverage Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import MITRECoverageAnalyzerState
from .nodes import (
    calculate_coverage,
    generate_report,
    identify_gaps,
    inventory_detections,
    map_to_mitre,
    recommend_rules,
)
from .tools import MITRECoverageAnalyzerToolkit


def _has_detections(state: Any) -> str:
    """Route based on whether detections were found."""
    if isinstance(state, dict):
        dets = state.get("detections_inventoried", [])
    else:
        dets = getattr(
            state,
            "detections_inventoried",
            [],
        )
    if dets:
        return "map_to_mitre"
    return "generate_report"


def build_graph(
    toolkit: MITRECoverageAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the MITRE Coverage Analyzer agent graph."""

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        s = (
            state.model_dump()
            if hasattr(state, "model_dump")
            else dict(state)
            if not isinstance(state, dict)
            else state
        )
        return await inventory_detections(s, toolkit)

    async def _map(state: Any) -> dict[str, Any]:
        s = (
            state.model_dump()
            if hasattr(state, "model_dump")
            else dict(state)
            if not isinstance(state, dict)
            else state
        )
        return await map_to_mitre(s, toolkit)

    async def _coverage(
        state: Any,
    ) -> dict[str, Any]:
        s = (
            state.model_dump()
            if hasattr(state, "model_dump")
            else dict(state)
            if not isinstance(state, dict)
            else state
        )
        return await calculate_coverage(s, toolkit)

    async def _gaps(state: Any) -> dict[str, Any]:
        s = (
            state.model_dump()
            if hasattr(state, "model_dump")
            else dict(state)
            if not isinstance(state, dict)
            else state
        )
        return await identify_gaps(s, toolkit)

    async def _recommend(
        state: Any,
    ) -> dict[str, Any]:
        s = (
            state.model_dump()
            if hasattr(state, "model_dump")
            else dict(state)
            if not isinstance(state, dict)
            else state
        )
        return await recommend_rules(s, toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        s = (
            state.model_dump()
            if hasattr(state, "model_dump")
            else dict(state)
            if not isinstance(state, dict)
            else state
        )
        return await generate_report(s, toolkit)

    graph = StateGraph(MITRECoverageAnalyzerState)
    graph.add_node("inventory_detections", _inventory)
    graph.add_node("map_to_mitre", _map)
    graph.add_node("calculate_coverage", _coverage)
    graph.add_node("identify_gaps", _gaps)
    graph.add_node("recommend_rules", _recommend)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("inventory_detections")
    graph.add_conditional_edges(
        "inventory_detections",
        _has_detections,
        {
            "map_to_mitre": "map_to_mitre",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("map_to_mitre", "calculate_coverage")
    graph.add_edge(
        "calculate_coverage",
        "identify_gaps",
    )
    graph.add_edge("identify_gaps", "recommend_rules")
    graph.add_edge("recommend_rules", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_mitre_coverage_analyzer_graph(
    siem_client: Any | None = None,
    edr_client: Any | None = None,
    mitre_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the MITRE Coverage Analyzer graph."""
    toolkit = MITRECoverageAnalyzerToolkit(
        siem_client=siem_client,
        edr_client=edr_client,
        mitre_db=mitre_db,
    )
    return build_graph(toolkit)
