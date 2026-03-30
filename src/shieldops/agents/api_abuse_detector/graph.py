"""LangGraph workflow for the API Abuse Detector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.api_abuse_detector.models import (
    ApiAbuseDetectorState,
)
from shieldops.agents.api_abuse_detector.nodes import (
    analyze_patterns,
    apply_mitigation,
    classify_threat,
    collect_traffic,
    detect_abuse,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "api_abuse_detector"


def _should_analyze(
    state: ApiAbuseDetectorState,
) -> str:
    """Route after traffic collection based on results."""
    if state.error:
        return "generate_report"
    if state.traffic_samples:
        return "analyze_patterns"
    return "generate_report"


def _should_mitigate(
    state: ApiAbuseDetectorState,
) -> str:
    """Route after classification based on threat level."""
    level_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if level_order.get(state.max_threat_level, 0) >= 2:
        return "apply_mitigation"
    return "generate_report"


def create_api_abuse_detector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the API Abuse Detector LangGraph.

    Workflow:
        collect_traffic
          -> [has_samples?] -> analyze_patterns
          -> detect_abuse
          -> classify_threat
          -> [medium+?] -> apply_mitigation
          -> generate_report
    """
    graph = StateGraph(ApiAbuseDetectorState)

    graph.add_node(
        "collect_traffic",
        traced_node(
            f"{_AGENT}.collect_traffic",
            _AGENT,
        )(collect_traffic),
    )
    graph.add_node(
        "analyze_patterns",
        traced_node(
            f"{_AGENT}.analyze_patterns",
            _AGENT,
        )(analyze_patterns),
    )
    graph.add_node(
        "detect_abuse",
        traced_node(
            f"{_AGENT}.detect_abuse",
            _AGENT,
        )(detect_abuse),
    )
    graph.add_node(
        "classify_threat",
        traced_node(
            f"{_AGENT}.classify_threat",
            _AGENT,
        )(classify_threat),
    )
    graph.add_node(
        "apply_mitigation",
        traced_node(
            f"{_AGENT}.apply_mitigation",
            _AGENT,
        )(apply_mitigation),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_traffic")
    graph.add_conditional_edges(
        "collect_traffic",
        _should_analyze,
        {
            "analyze_patterns": "analyze_patterns",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_patterns", "detect_abuse")
    graph.add_edge("detect_abuse", "classify_threat")
    graph.add_conditional_edges(
        "classify_threat",
        _should_mitigate,
        {
            "apply_mitigation": "apply_mitigation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("apply_mitigation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
