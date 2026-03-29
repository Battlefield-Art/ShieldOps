"""Dark Web Monitor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.dark_web_monitor.models import DarkWebMonitorState
from shieldops.agents.dark_web_monitor.nodes import (
    alert,
    assess_risk,
    crawl_sources,
    extract_mentions,
    match_assets,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "dark_web_monitor"


def _check_error(state: DarkWebMonitorState) -> str:
    return "report" if state.error else "next"


def create_dark_web_monitor_graph() -> StateGraph:
    """Build the Dark Web Monitor workflow."""
    graph = StateGraph(DarkWebMonitorState)

    graph.add_node(
        "crawl_sources",
        traced_node(f"{_AGENT}.crawl_sources", _AGENT)(crawl_sources),
    )
    graph.add_node(
        "extract_mentions",
        traced_node(f"{_AGENT}.extract_mentions", _AGENT)(extract_mentions),
    )
    graph.add_node(
        "match_assets",
        traced_node(f"{_AGENT}.match_assets", _AGENT)(match_assets),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "alert",
        traced_node(f"{_AGENT}.alert", _AGENT)(alert),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("crawl_sources")

    graph.add_conditional_edges(
        "crawl_sources",
        _check_error,
        {"next": "extract_mentions", "report": "report"},
    )
    graph.add_conditional_edges(
        "extract_mentions",
        _check_error,
        {"next": "match_assets", "report": "report"},
    )
    graph.add_conditional_edges(
        "match_assets",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_risk",
        _check_error,
        {"next": "alert", "report": "report"},
    )
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph
