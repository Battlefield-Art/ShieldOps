"""LangGraph workflow definition for the Dark Web
Intelligence Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.dark_web_intelligence.models import (
    DarkWebIntelligenceState,
)
from shieldops.agents.dark_web_intelligence.nodes import (
    analyze_threats,
    assess_credibility,
    collect_mentions,
    generate_report,
    monitor_forums,
    send_alerts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "dark_web_intelligence"


def _should_alert(
    state: DarkWebIntelligenceState,
) -> str:
    """Route after credibility: alert if critical
    threats exist, otherwise report."""
    if state.error:
        return "generate_report"
    if state.critical_threats > 0:
        return "send_alerts"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Dark Web Intelligence workflow.

    Workflow:
        monitor_forums -> collect_mentions
            -> analyze_threats -> assess_credibility
            -> [critical? -> send_alerts]
            -> generate_report -> END
    """
    graph = StateGraph(DarkWebIntelligenceState)

    graph.add_node(
        "monitor_forums",
        traced_node(f"{_AGENT}.monitor_forums", _AGENT)(monitor_forums),
    )
    graph.add_node(
        "collect_mentions",
        traced_node(f"{_AGENT}.collect_mentions", _AGENT)(collect_mentions),
    )
    graph.add_node(
        "analyze_threats",
        traced_node(f"{_AGENT}.analyze_threats", _AGENT)(analyze_threats),
    )
    graph.add_node(
        "assess_credibility",
        traced_node(f"{_AGENT}.assess_credibility", _AGENT)(assess_credibility),
    )
    graph.add_node(
        "send_alerts",
        traced_node(f"{_AGENT}.send_alerts", _AGENT)(send_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("monitor_forums")
    graph.add_edge("monitor_forums", "collect_mentions")
    graph.add_edge("collect_mentions", "analyze_threats")
    graph.add_edge("analyze_threats", "assess_credibility")
    graph.add_conditional_edges(
        "assess_credibility",
        _should_alert,
        {
            "send_alerts": "send_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("send_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_dark_web_intelligence_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Dark Web Intelligence graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
