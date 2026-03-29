"""Physical Access Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AlertLevel, PhysicalAccessMonitorState
from .nodes import (
    analyze_patterns,
    detect_anomalies,
    evaluate_policies,
    generate_alerts,
    generate_report,
    ingest_events,
)
from .tools import PhysicalAccessMonitorToolkit

_CRITICAL_LEVELS = {
    AlertLevel.CRITICAL.value,
    AlertLevel.HIGH.value,
}


def _needs_alerts(state: Any) -> str:
    """Route based on whether anomalies require alerts."""
    if hasattr(state, "anomalies"):
        anomalies = state.anomalies
        violations = state.policy_violations
    else:
        anomalies = state.get("anomalies", [])
        violations = state.get("policy_violations", [])

    for anom in anomalies:
        level = anom.get("alert_level", "") if isinstance(anom, dict) else anom.alert_level
        if level in _CRITICAL_LEVELS:
            return "generate_alerts"

    if violations:
        return "generate_alerts"

    return "report"


def build_graph(
    toolkit: PhysicalAccessMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Physical Access Monitor graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_events(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_patterns(
            _to_dict(state),
            toolkit,
        )

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _evaluate(state: Any) -> dict[str, Any]:
        return await evaluate_policies(
            _to_dict(state),
            toolkit,
        )

    async def _alert(state: Any) -> dict[str, Any]:
        return await generate_alerts(
            _to_dict(state),
            toolkit,
        )

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(PhysicalAccessMonitorState)
    graph.add_node("ingest_events", _ingest)
    graph.add_node("analyze_patterns", _analyze)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("evaluate_policies", _evaluate)
    graph.add_node("generate_alerts", _alert)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("ingest_events")
    graph.add_edge("ingest_events", "analyze_patterns")
    graph.add_edge("analyze_patterns", "detect_anomalies")
    graph.add_edge("detect_anomalies", "evaluate_policies")
    graph.add_conditional_edges(
        "evaluate_policies",
        _needs_alerts,
        {
            "generate_alerts": "generate_alerts",
            "report": "generate_report",
        },
    )
    graph.add_edge("generate_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_physical_access_monitor_graph(
    access_system: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Physical Access Monitor graph."""
    toolkit = PhysicalAccessMonitorToolkit(
        access_system=access_system,
    )
    return build_graph(toolkit)
