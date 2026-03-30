"""SLA Violation Detector — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import SLAViolationDetectorState
from .nodes import (
    calculate_impact,
    collect_metrics,
    detect_violations,
    evaluate_thresholds,
    notify_owners,
    report,
)
from .tools import SLAViolationDetectorToolkit

_AGENT = "sla_violation_detector"


def _check_error(
    state: SLAViolationDetectorState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: SLAViolationDetectorToolkit,
) -> StateGraph:
    """Build the SLA Violation Detector graph."""

    def _d(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(s: Any) -> dict[str, Any]:
        return await collect_metrics(_d(s))

    async def _evaluate(s: Any) -> dict[str, Any]:
        return await evaluate_thresholds(_d(s))

    async def _detect(s: Any) -> dict[str, Any]:
        return await detect_violations(_d(s))

    async def _impact(s: Any) -> dict[str, Any]:
        return await calculate_impact(_d(s))

    async def _notify(s: Any) -> dict[str, Any]:
        return await notify_owners(_d(s))

    async def _report(s: Any) -> dict[str, Any]:
        return await report(_d(s))

    g = StateGraph(SLAViolationDetectorState)
    g.add_node(
        "collect_metrics",
        traced_node("svd.collect", _AGENT)(_collect),
    )
    g.add_node(
        "evaluate_thresholds",
        traced_node("svd.evaluate", _AGENT)(_evaluate),
    )
    g.add_node(
        "detect_violations",
        traced_node("svd.detect", _AGENT)(_detect),
    )
    g.add_node(
        "calculate_impact",
        traced_node("svd.impact", _AGENT)(_impact),
    )
    g.add_node(
        "notify_owners",
        traced_node("svd.notify", _AGENT)(_notify),
    )
    g.add_node(
        "report",
        traced_node("svd.report", _AGENT)(_report),
    )

    g.set_entry_point("collect_metrics")
    g.add_edge("collect_metrics", "evaluate_thresholds")
    g.add_edge(
        "evaluate_thresholds",
        "detect_violations",
    )
    g.add_edge("detect_violations", "calculate_impact")
    g.add_edge("calculate_impact", "notify_owners")
    g.add_edge("notify_owners", "report")
    g.add_edge("report", END)

    return g


def create_sla_violation_detector_graph(
    metrics_service: Any | None = None,
    notification_service: Any | None = None,
) -> StateGraph:
    """Factory to create the SLA violation detector."""
    toolkit = SLAViolationDetectorToolkit(
        metrics_service=metrics_service,
        notification_service=notification_service,
    )
    return build_graph(toolkit)
