"""LangGraph workflow for the Identity Threat Detector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.identity_threat_detector.models import (
    IdentityThreatDetectorState,
)
from shieldops.agents.identity_threat_detector.nodes import (
    analyze_behavior,
    assess_risk,
    collect_auth_events,
    detect_anomalies,
    generate_report,
    respond_to_threats,
)
from shieldops.agents.tracing import traced_node

_AGENT = "identity_threat_detector"


def _should_analyze(
    state: IdentityThreatDetectorState,
) -> str:
    """Route after collection based on results."""
    if state.error:
        return "generate_report"
    if state.auth_events:
        return "analyze_behavior"
    return "generate_report"


def _should_respond(
    state: IdentityThreatDetectorState,
) -> str:
    """Route after risk assessment — respond if high risk."""
    if state.max_risk_score > 50.0:
        return "respond_to_threats"
    return "generate_report"


def create_identity_threat_detector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Identity Threat Detector LangGraph.

    Workflow:
        collect_auth_events
          -> [has_events?] -> analyze_behavior
          -> detect_anomalies
          -> assess_risk
          -> [high_risk?] -> respond_to_threats
          -> generate_report
    """
    graph = StateGraph(IdentityThreatDetectorState)

    graph.add_node(
        "collect_auth_events",
        traced_node(
            f"{_AGENT}.collect_auth_events",
            _AGENT,
        )(collect_auth_events),
    )
    graph.add_node(
        "analyze_behavior",
        traced_node(
            f"{_AGENT}.analyze_behavior",
            _AGENT,
        )(analyze_behavior),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(
            f"{_AGENT}.detect_anomalies",
            _AGENT,
        )(detect_anomalies),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "respond_to_threats",
        traced_node(
            f"{_AGENT}.respond_to_threats",
            _AGENT,
        )(respond_to_threats),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_auth_events")
    graph.add_conditional_edges(
        "collect_auth_events",
        _should_analyze,
        {
            "analyze_behavior": "analyze_behavior",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_behavior", "detect_anomalies")
    graph.add_edge("detect_anomalies", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _should_respond,
        {
            "respond_to_threats": "respond_to_threats",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "respond_to_threats",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph
