"""LangGraph workflow for the Log Anomaly Detector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.log_anomaly_detector.models import (
    LogAnomalyDetectorState,
)
from shieldops.agents.log_anomaly_detector.nodes import (
    correlate_events,
    detect_anomalies,
    generate_report,
    ingest_logs,
    parse_patterns,
    prioritize_alerts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "log_anomaly_detector"


def _should_parse(
    state: LogAnomalyDetectorState,
) -> str:
    """Route after ingestion based on results."""
    if state.error:
        return "generate_report"
    if state.ingested_logs:
        return "parse_patterns"
    return "generate_report"


def _should_correlate(
    state: LogAnomalyDetectorState,
) -> str:
    """Route after anomaly detection."""
    if len(state.detected_anomalies) > 1:
        return "correlate_events"
    return "prioritize_alerts"


def create_log_anomaly_detector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Log Anomaly Detector LangGraph.

    Workflow:
        ingest_logs
          -> [has_logs?] -> parse_patterns
          -> detect_anomalies
          -> [multiple_anomalies?] -> correlate_events
          -> prioritize_alerts
          -> generate_report
    """
    graph = StateGraph(LogAnomalyDetectorState)

    graph.add_node(
        "ingest_logs",
        traced_node(
            f"{_AGENT}.ingest_logs",
            _AGENT,
        )(ingest_logs),
    )
    graph.add_node(
        "parse_patterns",
        traced_node(
            f"{_AGENT}.parse_patterns",
            _AGENT,
        )(parse_patterns),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(
            f"{_AGENT}.detect_anomalies",
            _AGENT,
        )(detect_anomalies),
    )
    graph.add_node(
        "correlate_events",
        traced_node(
            f"{_AGENT}.correlate_events",
            _AGENT,
        )(correlate_events),
    )
    graph.add_node(
        "prioritize_alerts",
        traced_node(
            f"{_AGENT}.prioritize_alerts",
            _AGENT,
        )(prioritize_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("ingest_logs")
    graph.add_conditional_edges(
        "ingest_logs",
        _should_parse,
        {
            "parse_patterns": "parse_patterns",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("parse_patterns", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        _should_correlate,
        {
            "correlate_events": "correlate_events",
            "prioritize_alerts": "prioritize_alerts",
        },
    )
    graph.add_edge("correlate_events", "prioritize_alerts")
    graph.add_edge("prioritize_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
