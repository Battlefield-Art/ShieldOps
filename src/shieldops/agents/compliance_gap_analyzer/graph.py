"""Compliance Gap Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceGapAnalyzerState
from .nodes import (
    build_report,
    generate_plan,
    identify_gaps,
    map_requirements,
    prioritize_risks,
    scan_posture,
)
from .tools import ComplianceGapAnalyzerToolkit


def build_graph(
    toolkit: ComplianceGapAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Gap Analyzer graph."""

    def _to_dict(
        state: Any,
    ) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _scan_posture(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_posture(
            _to_dict(state),
            toolkit,
        )

    async def _map_requirements(
        state: Any,
    ) -> dict[str, Any]:
        return await map_requirements(
            _to_dict(state),
            toolkit,
        )

    async def _identify_gaps(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_gaps(
            _to_dict(state),
            toolkit,
        )

    async def _prioritize_risks(
        state: Any,
    ) -> dict[str, Any]:
        return await prioritize_risks(
            _to_dict(state),
            toolkit,
        )

    async def _generate_plan(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_plan(
            _to_dict(state),
            toolkit,
        )

    async def _build_report(
        state: Any,
    ) -> dict[str, Any]:
        return await build_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(ComplianceGapAnalyzerState)
    graph.add_node("scan_posture", _scan_posture)
    graph.add_node(
        "map_requirements",
        _map_requirements,
    )
    graph.add_node(
        "identify_gaps",
        _identify_gaps,
    )
    graph.add_node(
        "prioritize_risks",
        _prioritize_risks,
    )
    graph.add_node(
        "generate_plan",
        _generate_plan,
    )
    graph.add_node(
        "build_report",
        _build_report,
    )

    graph.set_entry_point("scan_posture")
    graph.add_edge(
        "scan_posture",
        "map_requirements",
    )
    graph.add_edge(
        "map_requirements",
        "identify_gaps",
    )
    graph.add_edge(
        "identify_gaps",
        "prioritize_risks",
    )
    graph.add_edge(
        "prioritize_risks",
        "generate_plan",
    )
    graph.add_edge(
        "generate_plan",
        "build_report",
    )
    graph.add_edge("build_report", END)

    return graph


def create_compliance_gap_analyzer_graph(
    toolkit: ComplianceGapAnalyzerToolkit | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory for the Compliance Gap Analyzer."""
    if toolkit is None:
        toolkit = ComplianceGapAnalyzerToolkit()
    return build_graph(toolkit)
