"""Predictive Scaler Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PredictiveScalerState
from .nodes import (
    analyze_patterns,
    collect_metrics,
    execute_scaling,
    generate_report,
    plan_scaling,
    predict_demand,
)
from .tools import PredictiveScalerToolkit


def build_graph(
    toolkit: PredictiveScalerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Predictive Scaler graph.

    Flow:
        collect_metrics -> analyze_patterns
        -> predict_demand -> plan_scaling
        -> execute_scaling -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_metrics(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_patterns(
            _to_dict(state),
            toolkit,
        )

    async def _predict(
        state: Any,
    ) -> dict[str, Any]:
        return await predict_demand(
            _to_dict(state),
            toolkit,
        )

    async def _plan(
        state: Any,
    ) -> dict[str, Any]:
        return await plan_scaling(
            _to_dict(state),
            toolkit,
        )

    async def _execute(
        state: Any,
    ) -> dict[str, Any]:
        return await execute_scaling(
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

    graph = StateGraph(PredictiveScalerState)
    graph.add_node("collect_metrics", _collect)
    graph.add_node("analyze_patterns", _analyze)
    graph.add_node("predict_demand", _predict)
    graph.add_node("plan_scaling", _plan)
    graph.add_node("execute_scaling", _execute)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_metrics")
    graph.add_edge(
        "collect_metrics",
        "analyze_patterns",
    )
    graph.add_edge(
        "analyze_patterns",
        "predict_demand",
    )
    graph.add_edge(
        "predict_demand",
        "plan_scaling",
    )
    graph.add_edge(
        "plan_scaling",
        "execute_scaling",
    )
    graph.add_edge(
        "execute_scaling",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_predictive_scaler_graph(
    metrics_api: Any | None = None,
    infra_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Predictive Scaler graph."""
    toolkit = PredictiveScalerToolkit(
        metrics_api=metrics_api,
        infra_api=infra_api,
    )
    return build_graph(toolkit)
