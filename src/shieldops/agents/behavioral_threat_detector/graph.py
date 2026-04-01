"""LangGraph workflow for the Behavioral Threat Detector."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.behavioral_threat_detector.models import (
    BehavioralThreatDetectorState,
)
from shieldops.agents.behavioral_threat_detector.nodes import (
    build_baselines,
    collect_behaviors,
    detect_deviations,
    generate_alerts,
    generate_report,
    score_threats,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "behavioral_threat_detector"


def _check_error(
    state: BehavioralThreatDetectorState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "generate_report"
    return "next"


def should_generate_alerts(
    state: BehavioralThreatDetectorState,
) -> str:
    """Route: generate alerts if threats scored."""
    if state.error:
        return "generate_report"
    if state.threat_scores:
        return "generate_alerts"
    return "generate_report"


def create_behavioral_threat_detector_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Behavioral Threat Detector LangGraph workflow.

    Workflow:
        collect_behaviors
        -> build_baselines
        -> detect_deviations
        -> score_threats
        -> [threats? -> generate_alerts]
        -> generate_report
        -> END
    """
    graph = StateGraph(BehavioralThreatDetectorState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "collect_behaviors",
        traced_node(
            f"{_AGENT}.collect_behaviors",
            _AGENT,
        )(collect_behaviors),
    )
    graph.add_node(
        "build_baselines",
        traced_node(
            f"{_AGENT}.build_baselines",
            _AGENT,
        )(build_baselines),
    )
    graph.add_node(
        "detect_deviations",
        traced_node(
            f"{_AGENT}.detect_deviations",
            _AGENT,
        )(detect_deviations),
    )
    graph.add_node(
        "score_threats",
        traced_node(
            f"{_AGENT}.score_threats",
            _AGENT,
        )(score_threats),
    )
    graph.add_node(
        "generate_alerts",
        traced_node(
            f"{_AGENT}.generate_alerts",
            _AGENT,
        )(generate_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_behaviors")
    graph.add_conditional_edges(
        "collect_behaviors",
        _check_error,
        {
            "next": "build_baselines",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "build_baselines",
        _check_error,
        {
            "next": "detect_deviations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_deviations", "score_threats")
    graph.add_conditional_edges(
        "score_threats",
        should_generate_alerts,
        {
            "generate_alerts": "generate_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
