"""FinOps Forecaster Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import FinopsForecasterState
from .nodes import (
    analyze_trends,
    collect_history,
    detect_anomalies,
    forecast_spend,
    generate_report,
    recommend_commitments,
)
from .tools import FinopsForecasterToolkit


def build_graph(
    toolkit: FinopsForecasterToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the FinOps Forecaster graph.

    Flow:
        collect_history -> analyze_trends
        -> forecast_spend -> detect_anomalies
        -> recommend_commitments -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_history(
            _to_dict(state),
            toolkit,
        )

    async def _trends(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_trends(
            _to_dict(state),
            toolkit,
        )

    async def _forecast(
        state: Any,
    ) -> dict[str, Any]:
        return await forecast_spend(
            _to_dict(state),
            toolkit,
        )

    async def _anomalies(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _commitments(
        state: Any,
    ) -> dict[str, Any]:
        return await recommend_commitments(
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

    graph = StateGraph(FinopsForecasterState)
    graph.add_node("collect_history", _collect)
    graph.add_node("analyze_trends", _trends)
    graph.add_node("forecast_spend", _forecast)
    graph.add_node("detect_anomalies", _anomalies)
    graph.add_node(
        "recommend_commitments",
        _commitments,
    )
    graph.add_node("report", _report)

    graph.set_entry_point("collect_history")
    graph.add_edge(
        "collect_history",
        "analyze_trends",
    )
    graph.add_edge(
        "analyze_trends",
        "forecast_spend",
    )
    graph.add_edge(
        "forecast_spend",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "recommend_commitments",
    )
    graph.add_edge(
        "recommend_commitments",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_finops_forecaster_graph(
    billing_api: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the FinOps Forecaster graph."""
    toolkit = FinopsForecasterToolkit(
        billing_api=billing_api,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
