"""Security Ops Dashboard Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityOpsDashboardState
from .nodes import (
    build_views,
    calculate_kpis,
    collect_metrics,
    detect_anomalies,
    generate_insights,
    generate_report,
)
from .tools import SecurityOpsDashboardToolkit


def build_graph(
    toolkit: SecurityOpsDashboardToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Ops Dashboard graph.

    Flow:
        collect_metrics -> calculate_kpis
        -> detect_anomalies -> generate_insights
        -> build_views -> report
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

    async def _calculate(
        state: Any,
    ) -> dict[str, Any]:
        return await calculate_kpis(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _insights(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_insights(
            _to_dict(state),
            toolkit,
        )

    async def _views(
        state: Any,
    ) -> dict[str, Any]:
        return await build_views(
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

    graph = StateGraph(SecurityOpsDashboardState)
    graph.add_node("collect_metrics", _collect)
    graph.add_node("calculate_kpis", _calculate)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("generate_insights", _insights)
    graph.add_node("build_views", _views)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_metrics")
    graph.add_edge(
        "collect_metrics",
        "calculate_kpis",
    )
    graph.add_edge(
        "calculate_kpis",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "generate_insights",
    )
    graph.add_edge(
        "generate_insights",
        "build_views",
    )
    graph.add_edge(
        "build_views",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_ops_dashboard_graph(
    metrics_api: Any | None = None,
    dashboard_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Ops Dashboard graph."""
    toolkit = SecurityOpsDashboardToolkit(
        metrics_api=metrics_api,
        dashboard_api=dashboard_api,
    )
    return build_graph(toolkit)
