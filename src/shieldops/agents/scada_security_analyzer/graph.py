"""SCADA Security Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.scada_security_analyzer.models import SCADASecurityAnalyzerState
from shieldops.agents.scada_security_analyzer.nodes import (
    analyze_traffic,
    assess_risk,
    check_firmware,
    detect_anomalies,
    discover_assets,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "scada_security_analyzer"


def _check_error(state: SCADASecurityAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_scada_security_analyzer_graph() -> StateGraph:
    """Build the SCADA Security Analyzer LangGraph workflow."""
    graph = StateGraph(SCADASecurityAnalyzerState)

    graph.add_node(
        "discover_assets",
        traced_node(f"{_AGENT}.discover_assets", _AGENT)(discover_assets),
    )
    graph.add_node(
        "analyze_traffic",
        traced_node(f"{_AGENT}.analyze_traffic", _AGENT)(analyze_traffic),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "check_firmware",
        traced_node(f"{_AGENT}.check_firmware", _AGENT)(check_firmware),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_assets")

    graph.add_conditional_edges(
        "discover_assets",
        _check_error,
        {"next": "analyze_traffic", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_traffic",
        _check_error,
        {"next": "detect_anomalies", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {"next": "check_firmware", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_firmware",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_edge("assess_risk", "report")
    graph.add_edge("report", END)

    return graph
