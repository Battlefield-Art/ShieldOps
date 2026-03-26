"""Capacity Planner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CapacityPlannerState
from .nodes import (
    collect_metrics,
    forecast_demand,
    generate_report,
    identify_bottlenecks,
    plan_scaling,
    recommend,
)
from .tools import CapacityPlannerToolkit


def _has_bottlenecks(state: Any) -> str:
    """Route based on whether bottlenecks were found."""
    if hasattr(state, "model_dump"):
        data = state.model_dump()
    elif isinstance(state, dict):
        data = state
    else:
        data = dict(state)

    bottlenecks = data.get("bottlenecks", [])
    if bottlenecks:
        return "plan_scaling"
    return "generate_report"


def build_graph(
    toolkit: CapacityPlannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Capacity Planner agent graph.

    Flow:
        collect_metrics -> forecast_demand -> identify_bottlenecks
            --(bottlenecks found)--> plan_scaling -> recommend -> generate_report
            --(no bottlenecks)-----> generate_report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_metrics(_to_dict(state), toolkit)

    async def _forecast(state: Any) -> dict[str, Any]:
        return await forecast_demand(_to_dict(state), toolkit)

    async def _bottlenecks(state: Any) -> dict[str, Any]:
        return await identify_bottlenecks(_to_dict(state), toolkit)

    async def _plan(state: Any) -> dict[str, Any]:
        return await plan_scaling(_to_dict(state), toolkit)

    async def _recommend(state: Any) -> dict[str, Any]:
        return await recommend(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CapacityPlannerState)
    graph.add_node("collect_metrics", _collect)
    graph.add_node("forecast_demand", _forecast)
    graph.add_node("identify_bottlenecks", _bottlenecks)
    graph.add_node("plan_scaling", _plan)
    graph.add_node("recommend", _recommend)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("collect_metrics")
    graph.add_edge("collect_metrics", "forecast_demand")
    graph.add_edge("forecast_demand", "identify_bottlenecks")

    graph.add_conditional_edges(
        "identify_bottlenecks",
        _has_bottlenecks,
        {
            "plan_scaling": "plan_scaling",
            "generate_report": "generate_report",
        },
    )

    graph.add_edge("plan_scaling", "recommend")
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_capacity_planner_graph(
    metrics_client: Any | None = None,
    cloud_provider: Any | None = None,
    cost_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Capacity Planner agent graph with dependencies."""
    toolkit = CapacityPlannerToolkit(
        metrics_client=metrics_client,
        cloud_provider=cloud_provider,
        cost_api=cost_api,
    )
    return build_graph(toolkit)
