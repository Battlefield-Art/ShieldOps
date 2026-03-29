"""LangGraph workflow definition for the Network Traffic Analyzer Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.network_traffic_analyzer.models import (
    NetworkTrafficAnalyzerState,
)
from shieldops.agents.network_traffic_analyzer.nodes import (
    analyze_protocols,
    classify_threats,
    correlate,
    detect_anomalies,
    ingest_flows,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "network_traffic_analyzer"


def _route_after_ingest(
    state: NetworkTrafficAnalyzerState,
) -> str:
    if state.error:
        return "report"
    return "detect_anomalies"


def _route_after_detect(
    state: NetworkTrafficAnalyzerState,
) -> str:
    if state.error:
        return "report"
    return "classify_threats"


def _route_after_classify(
    state: NetworkTrafficAnalyzerState,
) -> str:
    if state.error:
        return "report"
    return "analyze_protocols"


def _route_after_protocols(
    state: NetworkTrafficAnalyzerState,
) -> str:
    if state.error:
        return "report"
    return "correlate"


def _route_after_correlate(
    state: NetworkTrafficAnalyzerState,
) -> str:
    return "report"


def create_network_traffic_analyzer_graph() -> StateGraph:
    """Build the Network Traffic Analyzer LangGraph workflow.

    Workflow:
        ingest_flows -> detect_anomalies -> classify_threats
        -> analyze_protocols -> correlate -> report -> END

    Error at any stage short-circuits to report.
    """
    graph = StateGraph(NetworkTrafficAnalyzerState)

    graph.add_node(
        "ingest_flows",
        traced_node(
            f"{_AGENT}.ingest_flows",
            _AGENT,
        )(ingest_flows),
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
        "analyze_protocols",
        traced_node(
            f"{_AGENT}.analyze_protocols",
            _AGENT,
        )(analyze_protocols),
    )
    graph.add_node(
        "correlate",
        traced_node(
            f"{_AGENT}.correlate",
            _AGENT,
        )(correlate),
    )
    graph.add_node(
        "report",
        traced_node(
            f"{_AGENT}.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("ingest_flows")

    graph.add_conditional_edges(
        "ingest_flows",
        _route_after_ingest,
        {
            "detect_anomalies": "detect_anomalies",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _route_after_detect,
        {
            "classify_threats": "classify_threats",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "classify_threats",
        _route_after_classify,
        {
            "analyze_protocols": "analyze_protocols",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "analyze_protocols",
        _route_after_protocols,
        {
            "correlate": "correlate",
            "report": "report",
        },
    )
    graph.add_edge("correlate", "report")
    graph.add_edge("report", END)

    return graph
