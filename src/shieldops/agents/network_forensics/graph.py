"""LangGraph workflow for the Network Forensics Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.network_forensics.models import (
    NetworkForensicsState,
)
from shieldops.agents.network_forensics.nodes import (
    build_timeline,
    ingest_capture,
    map_exfiltration,
    reconstruct_sessions,
    report,
    trace_lateral,
)
from shieldops.agents.tracing import traced_node

_AGENT = "network_forensics"


def _check_error(
    state: NetworkForensicsState,
) -> str:
    if state.error:
        return "report"
    return "next"


def create_network_forensics_graph() -> StateGraph:
    """Build the Network Forensics LangGraph workflow."""
    graph = StateGraph(NetworkForensicsState)

    graph.add_node(
        "ingest_capture",
        traced_node(
            f"{_AGENT}.ingest_capture",
            _AGENT,
        )(ingest_capture),
    )
    graph.add_node(
        "reconstruct_sessions",
        traced_node(
            f"{_AGENT}.reconstruct_sessions",
            _AGENT,
        )(reconstruct_sessions),
    )
    graph.add_node(
        "build_timeline",
        traced_node(
            f"{_AGENT}.build_timeline",
            _AGENT,
        )(build_timeline),
    )
    graph.add_node(
        "trace_lateral",
        traced_node(
            f"{_AGENT}.trace_lateral",
            _AGENT,
        )(trace_lateral),
    )
    graph.add_node(
        "map_exfiltration",
        traced_node(
            f"{_AGENT}.map_exfiltration",
            _AGENT,
        )(map_exfiltration),
    )
    graph.add_node(
        "report",
        traced_node(
            f"{_AGENT}.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("ingest_capture")

    graph.add_conditional_edges(
        "ingest_capture",
        _check_error,
        {"next": "reconstruct_sessions", "report": "report"},
    )
    graph.add_conditional_edges(
        "reconstruct_sessions",
        _check_error,
        {"next": "build_timeline", "report": "report"},
    )
    graph.add_edge("build_timeline", "trace_lateral")
    graph.add_edge("trace_lateral", "map_exfiltration")
    graph.add_edge("map_exfiltration", "report")
    graph.add_edge("report", END)

    return graph
