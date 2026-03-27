"""Detection Gap Finder Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DetectionGapFinderState
from .nodes import (
    generate_report,
    identify_blind_spots,
    monitor_detections,
    prioritize_gaps,
    select_techniques,
    simulate_attacks,
)
from .tools import DetectionGapFinderToolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return dict(state) if not isinstance(state, dict) else state


def _has_techniques(state: Any) -> str:
    """Route based on technique selection."""
    if isinstance(state, dict):
        techs = state.get("techniques_selected", [])
    else:
        techs = getattr(
            state,
            "techniques_selected",
            [],
        )
    if techs:
        return "simulate_attacks"
    return "generate_report"


def build_graph(
    toolkit: DetectionGapFinderToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Detection Gap Finder agent graph."""

    async def _select(
        state: Any,
    ) -> dict[str, Any]:
        return await select_techniques(
            _to_dict(state),
            toolkit,
        )

    async def _simulate(
        state: Any,
    ) -> dict[str, Any]:
        return await simulate_attacks(
            _to_dict(state),
            toolkit,
        )

    async def _monitor(
        state: Any,
    ) -> dict[str, Any]:
        return await monitor_detections(
            _to_dict(state),
            toolkit,
        )

    async def _blind_spots(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_blind_spots(
            _to_dict(state),
            toolkit,
        )

    async def _prioritize(
        state: Any,
    ) -> dict[str, Any]:
        return await prioritize_gaps(
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

    graph = StateGraph(DetectionGapFinderState)
    graph.add_node("select_techniques", _select)
    graph.add_node("simulate_attacks", _simulate)
    graph.add_node("monitor_detections", _monitor)
    graph.add_node(
        "identify_blind_spots",
        _blind_spots,
    )
    graph.add_node("prioritize_gaps", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("select_techniques")
    graph.add_conditional_edges(
        "select_techniques",
        _has_techniques,
        {
            "simulate_attacks": "simulate_attacks",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "simulate_attacks",
        "monitor_detections",
    )
    graph.add_edge(
        "monitor_detections",
        "identify_blind_spots",
    )
    graph.add_edge(
        "identify_blind_spots",
        "prioritize_gaps",
    )
    graph.add_edge("prioritize_gaps", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_detection_gap_finder_graph(
    siem_client: Any | None = None,
    simulation_engine: Any | None = None,
    detection_monitor: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Detection Gap Finder graph."""
    toolkit = DetectionGapFinderToolkit(
        siem_client=siem_client,
        simulation_engine=simulation_engine,
        detection_monitor=detection_monitor,
    )
    return build_graph(toolkit)
