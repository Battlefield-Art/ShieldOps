"""Sensitive Data Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SensitiveDataMonitorState
from .nodes import (
    assess_exposure,
    classify_data,
    discover_data_sources,
    enforce_controls,
    report,
    scan_for_sensitive,
)
from .tools import SensitiveDataMonitorToolkit


def _has_exposures(state: Any) -> str:
    """Route based on whether exposure findings exist."""
    exposures = state.exposures if hasattr(state, "exposures") else state.get("exposures", [])
    if exposures:
        return "enforce"
    return "report"


def build_graph(
    toolkit: SensitiveDataMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Sensitive Data Monitor agent graph.

    Flow:
        discover_data_sources -> scan_for_sensitive
        -> classify_data -> assess_exposure
        -> (exposures?) -> enforce_controls -> report
                        |-> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_data_sources(_to_dict(state), toolkit)

    async def _scan(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_for_sensitive(_to_dict(state), toolkit)

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_data(_to_dict(state), toolkit)

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_exposure(_to_dict(state), toolkit)

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_controls(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(SensitiveDataMonitorState)
    graph.add_node("discover_data_sources", _discover)
    graph.add_node("scan_for_sensitive", _scan)
    graph.add_node("classify_data", _classify)
    graph.add_node("assess_exposure", _assess)
    graph.add_node("enforce_controls", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_data_sources")
    graph.add_edge("discover_data_sources", "scan_for_sensitive")
    graph.add_edge("scan_for_sensitive", "classify_data")
    graph.add_edge("classify_data", "assess_exposure")
    graph.add_conditional_edges(
        "assess_exposure",
        _has_exposures,
        {
            "enforce": "enforce_controls",
            "report": "report",
        },
    )
    graph.add_edge("enforce_controls", "report")
    graph.add_edge("report", END)

    return graph


def create_sensitive_data_monitor_graph(
    db_connector: Any | None = None,
    storage_connector: Any | None = None,
    ai_pipeline_connector: Any | None = None,
    control_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Sensitive Data Monitor graph."""
    toolkit = SensitiveDataMonitorToolkit(
        db_connector=db_connector,
        storage_connector=storage_connector,
        ai_pipeline_connector=ai_pipeline_connector,
        control_api=control_api,
    )
    return build_graph(toolkit)
