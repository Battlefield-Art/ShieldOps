"""Privileged Session Recorder Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.privileged_session_recorder.models import PrivilegedSessionRecorderState
from shieldops.agents.privileged_session_recorder.nodes import (
    archive,
    detect_anomalies,
    detect_session,
    monitor_commands,
    report,
    start_recording,
)
from shieldops.agents.tracing import traced_node

_AGENT = "privileged_session_recorder"


def _check_error(state: PrivilegedSessionRecorderState) -> str:
    return "report" if state.error else "next"


def create_privileged_session_recorder_graph() -> StateGraph:
    """Build the Privileged Session Recorder workflow."""
    graph = StateGraph(PrivilegedSessionRecorderState)

    graph.add_node(
        "detect_session",
        traced_node(f"{_AGENT}.detect_session", _AGENT)(detect_session),
    )
    graph.add_node(
        "start_recording",
        traced_node(f"{_AGENT}.start_recording", _AGENT)(start_recording),
    )
    graph.add_node(
        "monitor_commands",
        traced_node(f"{_AGENT}.monitor_commands", _AGENT)(monitor_commands),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "archive",
        traced_node(f"{_AGENT}.archive", _AGENT)(archive),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("detect_session")

    graph.add_conditional_edges(
        "detect_session",
        _check_error,
        {"next": "start_recording", "report": "report"},
    )
    graph.add_conditional_edges(
        "start_recording",
        _check_error,
        {"next": "monitor_commands", "report": "report"},
    )
    graph.add_conditional_edges(
        "monitor_commands",
        _check_error,
        {"next": "detect_anomalies", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {"next": "archive", "report": "report"},
    )
    graph.add_edge("archive", "report")
    graph.add_edge("report", END)

    return graph
