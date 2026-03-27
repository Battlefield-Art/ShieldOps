"""Compliance Gap Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceGapAnalyzerState
from .nodes import (
    assess_coverage,
    generate_remediation_plan,
    generate_report,
    identify_gaps,
    inventory_controls,
    map_to_frameworks,
)
from .tools import ComplianceGapAnalyzerToolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return dict(state) if not isinstance(state, dict) else state


def _has_controls(state: Any) -> str:
    """Route based on control inventory."""
    if isinstance(state, dict):
        ctrls = state.get(
            "controls_inventoried",
            [],
        )
    else:
        ctrls = getattr(
            state,
            "controls_inventoried",
            [],
        )
    if ctrls:
        return "map_to_frameworks"
    return "generate_report"


def build_graph(
    toolkit: ComplianceGapAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Gap Analyzer graph."""

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_controls(
            _to_dict(state),
            toolkit,
        )

    async def _map(
        state: Any,
    ) -> dict[str, Any]:
        return await map_to_frameworks(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_coverage(
            _to_dict(state),
            toolkit,
        )

    async def _gaps(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_gaps(
            _to_dict(state),
            toolkit,
        )

    async def _remediate(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_remediation_plan(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(ComplianceGapAnalyzerState)
    graph.add_node(
        "inventory_controls",
        _inventory,
    )
    graph.add_node("map_to_frameworks", _map)
    graph.add_node("assess_coverage", _assess)
    graph.add_node("identify_gaps", _gaps)
    graph.add_node(
        "generate_remediation_plan",
        _remediate,
    )
    graph.add_node("generate_report", _report)

    graph.set_entry_point("inventory_controls")
    graph.add_conditional_edges(
        "inventory_controls",
        _has_controls,
        {
            "map_to_frameworks": "map_to_frameworks",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "map_to_frameworks",
        "assess_coverage",
    )
    graph.add_edge(
        "assess_coverage",
        "identify_gaps",
    )
    graph.add_edge(
        "identify_gaps",
        "generate_remediation_plan",
    )
    graph.add_edge(
        "generate_remediation_plan",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_compliance_gap_analyzer_graph(
    compliance_db: Any | None = None,
    control_registry: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Compliance Gap Analyzer."""
    toolkit = ComplianceGapAnalyzerToolkit(
        compliance_db=compliance_db,
        control_registry=control_registry,
    )
    return build_graph(toolkit)
