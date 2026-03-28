"""LangGraph workflow definition for the Session Hijack Detector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.session_hijack_detector.models import (
    SessionHijackDetectorState,
)
from shieldops.agents.session_hijack_detector.nodes import (
    analyze_anomalies,
    assess_risk,
    collect_sessions,
    correlate_indicators,
    report,
    respond,
)
from shieldops.agents.tracing import traced_node


def should_correlate(
    state: SessionHijackDetectorState,
) -> str:
    """Route after anomaly analysis."""
    if state.error:
        return "report"
    if state.anomaly_count > 0:
        return "correlate_indicators"
    return "report"


def should_respond(
    state: SessionHijackDetectorState,
) -> str:
    """Route after risk assessment — respond or report."""
    if state.risk_score >= 40.0:
        return "respond"
    return "report"


def create_session_hijack_detector_graph() -> StateGraph[SessionHijackDetectorState]:
    """Build the Session Hijack Detector LangGraph workflow.

    Workflow:
        collect_sessions
          -> analyze_anomalies
          -> [anomalies? -> correlate_indicators
              -> assess_risk
              -> [risk>=40? -> respond]]
          -> report
    """
    graph = StateGraph(SessionHijackDetectorState)

    _agent = "session_hijack_detector"
    graph.add_node(
        "collect_sessions",
        traced_node(
            "session_hijack_detector.collect_sessions",
            _agent,
        )(collect_sessions),
    )
    graph.add_node(
        "analyze_anomalies",
        traced_node(
            "session_hijack_detector.analyze_anomalies",
            _agent,
        )(analyze_anomalies),
    )
    graph.add_node(
        "correlate_indicators",
        traced_node(
            "session_hijack_detector.correlate",
            _agent,
        )(correlate_indicators),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            "session_hijack_detector.assess_risk",
            _agent,
        )(assess_risk),
    )
    graph.add_node(
        "respond",
        traced_node(
            "session_hijack_detector.respond",
            _agent,
        )(respond),
    )
    graph.add_node(
        "report",
        traced_node(
            "session_hijack_detector.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("collect_sessions")
    graph.add_edge(
        "collect_sessions",
        "analyze_anomalies",
    )
    graph.add_conditional_edges(
        "analyze_anomalies",
        should_correlate,
        {
            "correlate_indicators": "correlate_indicators",
            "report": "report",
        },
    )
    graph.add_edge(
        "correlate_indicators",
        "assess_risk",
    )
    graph.add_conditional_edges(
        "assess_risk",
        should_respond,
        {
            "respond": "respond",
            "report": "report",
        },
    )
    graph.add_edge("respond", "report")
    graph.add_edge("report", END)

    return graph
