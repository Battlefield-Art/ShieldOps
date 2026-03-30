"""On-Call Optimizer — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import OnCallOptimizerState
from .nodes import (
    analyze_schedules,
    detect_burnout,
    evaluate_load,
    optimize_rotation,
    recommend_changes,
    report,
)
from .tools import OnCallOptimizerToolkit

_AGENT = "on_call_optimizer"


def _check_error(
    state: OnCallOptimizerState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: OnCallOptimizerToolkit,
) -> StateGraph:
    """Build the On-Call Optimizer graph."""

    def _d(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _analyze(s: Any) -> dict[str, Any]:
        return await analyze_schedules(_d(s))

    async def _load(s: Any) -> dict[str, Any]:
        return await evaluate_load(_d(s))

    async def _burnout(s: Any) -> dict[str, Any]:
        return await detect_burnout(_d(s))

    async def _optimize(s: Any) -> dict[str, Any]:
        return await optimize_rotation(_d(s))

    async def _recommend(s: Any) -> dict[str, Any]:
        return await recommend_changes(_d(s))

    async def _report(s: Any) -> dict[str, Any]:
        return await report(_d(s))

    g = StateGraph(OnCallOptimizerState)
    g.add_node(
        "analyze_schedules",
        traced_node("oco.analyze", _AGENT)(_analyze),
    )
    g.add_node(
        "evaluate_load",
        traced_node("oco.load", _AGENT)(_load),
    )
    g.add_node(
        "detect_burnout",
        traced_node("oco.burnout", _AGENT)(_burnout),
    )
    g.add_node(
        "optimize_rotation",
        traced_node("oco.optimize", _AGENT)(_optimize),
    )
    g.add_node(
        "recommend_changes",
        traced_node("oco.recommend", _AGENT)(_recommend),
    )
    g.add_node(
        "report",
        traced_node("oco.report", _AGENT)(_report),
    )

    g.set_entry_point("analyze_schedules")
    g.add_edge("analyze_schedules", "evaluate_load")
    g.add_edge("evaluate_load", "detect_burnout")
    g.add_edge("detect_burnout", "optimize_rotation")
    g.add_edge(
        "optimize_rotation",
        "recommend_changes",
    )
    g.add_edge("recommend_changes", "report")
    g.add_edge("report", END)

    return g


def create_on_call_optimizer_graph(
    schedule_service: Any | None = None,
    incident_service: Any | None = None,
) -> StateGraph:
    """Factory to create the on-call optimizer graph."""
    toolkit = OnCallOptimizerToolkit(
        schedule_service=schedule_service,
        incident_service=incident_service,
    )
    return build_graph(toolkit)
