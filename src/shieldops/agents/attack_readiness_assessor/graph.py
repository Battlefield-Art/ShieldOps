"""Attack Readiness Assessor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AttackReadinessAssessorState
from .nodes import (
    assess_detection,
    assess_prevention,
    assess_response,
    calculate_readiness,
    generate_report,
    select_scenarios,
)
from .tools import AttackReadinessAssessorToolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return dict(state) if not isinstance(state, dict) else state


def _has_scenarios(state: Any) -> str:
    """Route based on scenario selection."""
    if isinstance(state, dict):
        sels = state.get("scenarios_selected", [])
    else:
        sels = getattr(
            state,
            "scenarios_selected",
            [],
        )
    if sels:
        return "assess_prevention"
    return "generate_report"


def build_graph(
    toolkit: AttackReadinessAssessorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Attack Readiness Assessor graph."""

    async def _select(
        state: Any,
    ) -> dict[str, Any]:
        return await select_scenarios(
            _to_dict(state),
            toolkit,
        )

    async def _prevention(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_prevention(
            _to_dict(state),
            toolkit,
        )

    async def _detection(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_detection(
            _to_dict(state),
            toolkit,
        )

    async def _response(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_response(
            _to_dict(state),
            toolkit,
        )

    async def _readiness(
        state: Any,
    ) -> dict[str, Any]:
        return await calculate_readiness(
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

    graph = StateGraph(
        AttackReadinessAssessorState,
    )
    graph.add_node("select_scenarios", _select)
    graph.add_node(
        "assess_prevention",
        _prevention,
    )
    graph.add_node("assess_detection", _detection)
    graph.add_node("assess_response", _response)
    graph.add_node(
        "calculate_readiness",
        _readiness,
    )
    graph.add_node("generate_report", _report)

    graph.set_entry_point("select_scenarios")
    graph.add_conditional_edges(
        "select_scenarios",
        _has_scenarios,
        {
            "assess_prevention": "assess_prevention",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "assess_prevention",
        "assess_detection",
    )
    graph.add_edge(
        "assess_detection",
        "assess_response",
    )
    graph.add_edge(
        "assess_response",
        "calculate_readiness",
    )
    graph.add_edge(
        "calculate_readiness",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_attack_readiness_assessor_graph(
    threat_intel: Any | None = None,
    control_registry: Any | None = None,
    detection_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Attack Readiness graph."""
    toolkit = AttackReadinessAssessorToolkit(
        threat_intel=threat_intel,
        control_registry=control_registry,
        detection_engine=detection_engine,
    )
    return build_graph(toolkit)
