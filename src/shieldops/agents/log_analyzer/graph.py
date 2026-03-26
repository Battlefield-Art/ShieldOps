"""LangGraph workflow definition for the Log Analyzer Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.log_analyzer.models import AnomalySeverity, LogAnalyzerState
from shieldops.agents.log_analyzer.nodes import (
    collect_logs,
    correlate_events,
    detect_anomalies,
    generate_report,
    parse_patterns,
    send_alerts,
)
from shieldops.agents.tracing import traced_node


def should_alert(state: LogAnalyzerState) -> str:
    """Route to alerting if high/critical anomalies exist."""
    if state.error:
        return "generate_report"
    severity_rank = {
        AnomalySeverity.CRITICAL: 4,
        AnomalySeverity.HIGH: 3,
        AnomalySeverity.MEDIUM: 2,
        AnomalySeverity.LOW: 1,
        AnomalySeverity.INFO: 0,
    }
    if severity_rank.get(state.max_severity, 0) >= 3:
        return "send_alerts"
    return "generate_report"


def should_correlate(state: LogAnalyzerState) -> str:
    """Route to correlation if anomalies were detected."""
    if state.error:
        return "generate_report"
    if state.anomalies:
        return "correlate_events"
    return "generate_report"


def create_log_analyzer_graph() -> StateGraph[LogAnalyzerState]:
    """Build the Log Analyzer Agent LangGraph workflow.

    Workflow:
        collect_logs → parse_patterns → detect_anomalies
            → [anomalies? → correlate_events]
            → [high/critical? → send_alerts]
            → generate_report → END
    """
    graph = StateGraph(LogAnalyzerState)

    _agent = "log_analyzer"
    graph.add_node(
        "collect_logs",
        traced_node("log_analyzer.collect_logs", _agent)(collect_logs),
    )
    graph.add_node(
        "parse_patterns",
        traced_node("log_analyzer.parse_patterns", _agent)(parse_patterns),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node("log_analyzer.detect_anomalies", _agent)(detect_anomalies),
    )
    graph.add_node(
        "correlate_events",
        traced_node("log_analyzer.correlate_events", _agent)(correlate_events),
    )
    graph.add_node(
        "send_alerts",
        traced_node("log_analyzer.send_alerts", _agent)(send_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node("log_analyzer.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_logs")
    graph.add_edge("collect_logs", "parse_patterns")
    graph.add_edge("parse_patterns", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        should_correlate,
        {
            "correlate_events": "correlate_events",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "correlate_events",
        should_alert,
        {
            "send_alerts": "send_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("send_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
