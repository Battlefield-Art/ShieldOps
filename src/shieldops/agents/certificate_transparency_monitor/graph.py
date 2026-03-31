"""LangGraph workflow definition for the Certificate
Transparency Monitor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.certificate_transparency_monitor.models import (
    CertificateTransparencyMonitorState,
)
from shieldops.agents.certificate_transparency_monitor.nodes import (
    check_ownership,
    detect_anomalies,
    generate_report,
    monitor_logs,
    parse_certificates,
    send_alerts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "certificate_transparency_monitor"


def _should_alert(
    state: CertificateTransparencyMonitorState,
) -> str:
    """Route after ownership check: alert if anomalies
    confirmed or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.anomalies_found > 0:
        return "send_alerts"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Certificate Transparency Monitor
    LangGraph workflow.

    Workflow:
        monitor_logs -> parse_certificates
            -> detect_anomalies -> check_ownership
            -> [anomalies? -> send_alerts]
            -> generate_report -> END
    """
    graph = StateGraph(CertificateTransparencyMonitorState)

    graph.add_node(
        "monitor_logs",
        traced_node(f"{_AGENT}.monitor_logs", _AGENT)(monitor_logs),
    )
    graph.add_node(
        "parse_certificates",
        traced_node(f"{_AGENT}.parse_certificates", _AGENT)(parse_certificates),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "check_ownership",
        traced_node(f"{_AGENT}.check_ownership", _AGENT)(check_ownership),
    )
    graph.add_node(
        "send_alerts",
        traced_node(f"{_AGENT}.send_alerts", _AGENT)(send_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("monitor_logs")
    graph.add_edge("monitor_logs", "parse_certificates")
    graph.add_edge("parse_certificates", "detect_anomalies")
    graph.add_edge("detect_anomalies", "check_ownership")
    graph.add_conditional_edges(
        "check_ownership",
        _should_alert,
        {
            "send_alerts": "send_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("send_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_certificate_transparency_monitor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Certificate Transparency Monitor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
