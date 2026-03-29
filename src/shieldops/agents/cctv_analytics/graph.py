"""CCTV Analytics Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cctv_analytics.models import CCTVAnalyticsState
from shieldops.agents.cctv_analytics.nodes import (
    alert,
    analyze_behavior,
    classify_events,
    collect_feeds,
    detect_motion,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cctv_analytics"


def _check_error(state: CCTVAnalyticsState) -> str:
    return "report" if state.error else "next"


def create_cctv_analytics_graph() -> StateGraph:
    """Build the CCTV Analytics LangGraph workflow."""
    graph = StateGraph(CCTVAnalyticsState)

    graph.add_node(
        "collect_feeds",
        traced_node(f"{_AGENT}.collect_feeds", _AGENT)(collect_feeds),
    )
    graph.add_node(
        "detect_motion",
        traced_node(f"{_AGENT}.detect_motion", _AGENT)(detect_motion),
    )
    graph.add_node(
        "analyze_behavior",
        traced_node(f"{_AGENT}.analyze_behavior", _AGENT)(analyze_behavior),
    )
    graph.add_node(
        "classify_events",
        traced_node(f"{_AGENT}.classify_events", _AGENT)(classify_events),
    )
    graph.add_node(
        "alert",
        traced_node(f"{_AGENT}.alert", _AGENT)(alert),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_feeds")

    graph.add_conditional_edges(
        "collect_feeds",
        _check_error,
        {"next": "detect_motion", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_motion",
        _check_error,
        {"next": "analyze_behavior", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_behavior",
        _check_error,
        {"next": "classify_events", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_events",
        _check_error,
        {"next": "alert", "report": "report"},
    )
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph
