"""LangGraph workflow definition for the Regulatory
Change Monitor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.regulatory_change_monitor.models import (
    RegulatoryChangeMonitorState,
)
from shieldops.agents.regulatory_change_monitor.nodes import (
    assess_impact,
    generate_actions,
    generate_report,
    map_controls,
    monitor_sources,
    parse_changes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "regulatory_change_monitor"


def _should_map_controls(
    state: RegulatoryChangeMonitorState,
) -> str:
    """Route after impact assessment: map controls if
    impacts exist or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.impact_assessments:
        return "map_controls"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Regulatory Change Monitor LangGraph
    workflow.

    Workflow:
        monitor_sources -> parse_changes
            -> assess_impact
            -> [impacts? -> map_controls -> generate_actions]
            -> generate_report -> END
    """
    graph = StateGraph(RegulatoryChangeMonitorState)

    graph.add_node(
        "monitor_sources",
        traced_node(f"{_AGENT}.monitor_sources", _AGENT)(monitor_sources),
    )
    graph.add_node(
        "parse_changes",
        traced_node(f"{_AGENT}.parse_changes", _AGENT)(parse_changes),
    )
    graph.add_node(
        "assess_impact",
        traced_node(f"{_AGENT}.assess_impact", _AGENT)(assess_impact),
    )
    graph.add_node(
        "map_controls",
        traced_node(f"{_AGENT}.map_controls", _AGENT)(map_controls),
    )
    graph.add_node(
        "generate_actions",
        traced_node(f"{_AGENT}.generate_actions", _AGENT)(generate_actions),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("monitor_sources")
    graph.add_edge("monitor_sources", "parse_changes")
    graph.add_edge("parse_changes", "assess_impact")
    graph.add_conditional_edges(
        "assess_impact",
        _should_map_controls,
        {
            "map_controls": "map_controls",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("map_controls", "generate_actions")
    graph.add_edge("generate_actions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_regulatory_change_monitor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Regulatory Change Monitor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
