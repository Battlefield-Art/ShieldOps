"""LangGraph workflow for the Network Traffic Inspector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.network_traffic_inspector.models import (
    NetworkTrafficInspectorState,
)
from shieldops.agents.network_traffic_inspector.nodes import (
    analyze_protocols,
    capture_traffic,
    classify_threats,
    detect_anomalies,
    generate_alerts,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "network_traffic_inspector"


def _should_analyze(
    state: NetworkTrafficInspectorState,
) -> str:
    """Route after capture based on results."""
    if state.error:
        return "generate_report"
    if state.captured_flows:
        return "analyze_protocols"
    return "generate_report"


def _should_alert(
    state: NetworkTrafficInspectorState,
) -> str:
    """Route after classification based on threats."""
    if state.critical_threat_count > 0:
        return "generate_alerts"
    return "generate_report"


def create_network_traffic_inspector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Network Traffic Inspector LangGraph.

    Workflow:
        capture_traffic
          -> [has_flows?] -> analyze_protocols
          -> detect_anomalies
          -> classify_threats
          -> [critical?] -> generate_alerts
          -> generate_report
    """
    graph = StateGraph(NetworkTrafficInspectorState)

    graph.add_node(
        "capture_traffic",
        traced_node(
            f"{_AGENT}.capture_traffic",
            _AGENT,
        )(capture_traffic),
    )
    graph.add_node(
        "analyze_protocols",
        traced_node(
            f"{_AGENT}.analyze_protocols",
            _AGENT,
        )(analyze_protocols),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(
            f"{_AGENT}.detect_anomalies",
            _AGENT,
        )(detect_anomalies),
    )
    graph.add_node(
        "classify_threats",
        traced_node(
            f"{_AGENT}.classify_threats",
            _AGENT,
        )(classify_threats),
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

    # Edges
    graph.set_entry_point("capture_traffic")
    graph.add_conditional_edges(
        "capture_traffic",
        _should_analyze,
        {
            "analyze_protocols": "analyze_protocols",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_protocols", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify_threats")
    graph.add_conditional_edges(
        "classify_threats",
        _should_alert,
        {
            "generate_alerts": "generate_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
