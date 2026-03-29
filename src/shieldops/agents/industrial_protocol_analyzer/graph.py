"""Industrial Protocol Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.industrial_protocol_analyzer.models import IndustrialProtocolAnalyzerState
from shieldops.agents.industrial_protocol_analyzer.nodes import (
    assess_risk,
    capture_traffic,
    decode_protocols,
    detect_anomalies,
    report,
    validate_commands,
)
from shieldops.agents.tracing import traced_node

_AGENT = "industrial_protocol_analyzer"


def _check_error(state: IndustrialProtocolAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_industrial_protocol_analyzer_graph() -> StateGraph:
    """Build the Industrial Protocol Analyzer LangGraph workflow."""
    graph = StateGraph(IndustrialProtocolAnalyzerState)

    graph.add_node(
        "capture_traffic",
        traced_node(f"{_AGENT}.capture_traffic", _AGENT)(capture_traffic),
    )
    graph.add_node(
        "decode_protocols",
        traced_node(f"{_AGENT}.decode_protocols", _AGENT)(decode_protocols),
    )
    graph.add_node(
        "validate_commands",
        traced_node(f"{_AGENT}.validate_commands", _AGENT)(validate_commands),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("capture_traffic")

    graph.add_conditional_edges(
        "capture_traffic",
        _check_error,
        {"next": "decode_protocols", "report": "report"},
    )
    graph.add_conditional_edges(
        "decode_protocols",
        _check_error,
        {"next": "validate_commands", "report": "report"},
    )
    graph.add_conditional_edges(
        "validate_commands",
        _check_error,
        {"next": "detect_anomalies", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_edge("assess_risk", "report")
    graph.add_edge("report", END)

    return graph
