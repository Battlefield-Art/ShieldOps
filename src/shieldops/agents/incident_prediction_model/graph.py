"""Incident Prediction Model Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import IncidentPredictionModelState
from .nodes import (
    assess_confidence,
    collect_indicators,
    extract_features,
    generate_report,
    generate_warnings,
    run_model,
)
from .tools import IncidentPredictionModelToolkit


def build_graph(
    toolkit: IncidentPredictionModelToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Incident Prediction Model graph.

    Flow:
        collect_indicators -> extract_features
        -> run_model -> assess_confidence
        -> generate_warnings -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_indicators(
            _to_dict(state),
            toolkit,
        )

    async def _extract(
        state: Any,
    ) -> dict[str, Any]:
        return await extract_features(
            _to_dict(state),
            toolkit,
        )

    async def _run(
        state: Any,
    ) -> dict[str, Any]:
        return await run_model(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_confidence(
            _to_dict(state),
            toolkit,
        )

    async def _warn(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_warnings(
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

    graph = StateGraph(IncidentPredictionModelState)
    graph.add_node("collect_indicators", _collect)
    graph.add_node("extract_features", _extract)
    graph.add_node("run_model", _run)
    graph.add_node("assess_confidence", _assess)
    graph.add_node("generate_warnings", _warn)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_indicators")
    graph.add_edge(
        "collect_indicators",
        "extract_features",
    )
    graph.add_edge(
        "extract_features",
        "run_model",
    )
    graph.add_edge(
        "run_model",
        "assess_confidence",
    )
    graph.add_edge(
        "assess_confidence",
        "generate_warnings",
    )
    graph.add_edge(
        "generate_warnings",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_incident_prediction_model_graph(
    telemetry_source: Any | None = None,
    model_service: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Incident Prediction Model graph."""
    toolkit = IncidentPredictionModelToolkit(
        telemetry_source=telemetry_source,
        model_service=model_service,
    )
    return build_graph(toolkit)
