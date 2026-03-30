"""Session Manager Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.session_manager.models import (
    SessionManagerState,
)
from shieldops.agents.session_manager.nodes import (
    analyze_patterns,
    detect_hijacking,
    discover_sessions,
    enforce_timeouts,
    report,
    revoke_suspicious,
)
from shieldops.agents.tracing import traced_node

_AGENT = "session_manager"


def _check_error(state: SessionManagerState) -> str:
    return "report" if state.error else "next"


def create_session_manager_graph() -> StateGraph:
    """Build the Session Manager workflow."""
    graph = StateGraph(SessionManagerState)

    graph.add_node(
        "discover_sessions",
        traced_node("sm.discover_sessions", _AGENT)(discover_sessions),
    )
    graph.add_node(
        "analyze_patterns",
        traced_node("sm.analyze_patterns", _AGENT)(analyze_patterns),
    )
    graph.add_node(
        "detect_hijacking",
        traced_node("sm.detect_hijacking", _AGENT)(detect_hijacking),
    )
    graph.add_node(
        "enforce_timeouts",
        traced_node("sm.enforce_timeouts", _AGENT)(enforce_timeouts),
    )
    graph.add_node(
        "revoke_suspicious",
        traced_node("sm.revoke_suspicious", _AGENT)(revoke_suspicious),
    )
    graph.add_node(
        "report",
        traced_node("sm.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_sessions")

    graph.add_conditional_edges(
        "discover_sessions",
        _check_error,
        {
            "report": "report",
            "next": "analyze_patterns",
        },
    )
    graph.add_conditional_edges(
        "analyze_patterns",
        _check_error,
        {
            "report": "report",
            "next": "detect_hijacking",
        },
    )
    graph.add_conditional_edges(
        "detect_hijacking",
        _check_error,
        {
            "report": "report",
            "next": "enforce_timeouts",
        },
    )
    graph.add_conditional_edges(
        "enforce_timeouts",
        _check_error,
        {
            "report": "report",
            "next": "revoke_suspicious",
        },
    )
    graph.add_edge("revoke_suspicious", "report")
    graph.add_edge("report", END)

    return graph
