"""Behavioral Analytics Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.behavioral_analytics_engine.models import (
    BehavioralAnalyticsEngineState,
)
from shieldops.agents.behavioral_analytics_engine.nodes import (
    alert_violations,
    build_profiles,
    collect_telemetry,
    detect_anomalies,
    report,
    score_risk,
)
from shieldops.agents.tracing import traced_node

_AGENT = "behavioral_analytics_engine"


def _check_error(
    state: BehavioralAnalyticsEngineState,
) -> str:
    return "report" if state.error else "next"


def create_behavioral_analytics_engine_graph() -> StateGraph:
    """Build the Behavioral Analytics Engine workflow."""
    graph = StateGraph(BehavioralAnalyticsEngineState)

    graph.add_node(
        "collect_telemetry",
        traced_node("bae.collect_telemetry", _AGENT)(collect_telemetry),
    )
    graph.add_node(
        "build_profiles",
        traced_node("bae.build_profiles", _AGENT)(build_profiles),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node("bae.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "score_risk",
        traced_node("bae.score_risk", _AGENT)(score_risk),
    )
    graph.add_node(
        "alert_violations",
        traced_node("bae.alert_violations", _AGENT)(alert_violations),
    )
    graph.add_node(
        "report",
        traced_node("bae.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_telemetry")

    graph.add_conditional_edges(
        "collect_telemetry",
        _check_error,
        {"report": "report", "next": "build_profiles"},
    )
    graph.add_conditional_edges(
        "build_profiles",
        _check_error,
        {"report": "report", "next": "detect_anomalies"},
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {"report": "report", "next": "score_risk"},
    )
    graph.add_conditional_edges(
        "score_risk",
        _check_error,
        {"report": "report", "next": "alert_violations"},
    )
    graph.add_edge("alert_violations", "report")
    graph.add_edge("report", END)

    return graph
