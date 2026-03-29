"""Environmental Monitor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.environmental_monitor.models import EnvironmentalMonitorState
from shieldops.agents.environmental_monitor.nodes import (
    alert,
    assess_risk,
    check_thresholds,
    collect_readings,
    correlate_events,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "environmental_monitor"


def _check_error(state: EnvironmentalMonitorState) -> str:
    return "report" if state.error else "next"


def create_environmental_monitor_graph() -> StateGraph:
    """Build the Environmental Monitor LangGraph workflow."""
    graph = StateGraph(EnvironmentalMonitorState)

    graph.add_node(
        "collect_readings",
        traced_node(f"{_AGENT}.collect_readings", _AGENT)(collect_readings),
    )
    graph.add_node(
        "check_thresholds",
        traced_node(f"{_AGENT}.check_thresholds", _AGENT)(check_thresholds),
    )
    graph.add_node(
        "correlate_events",
        traced_node(f"{_AGENT}.correlate_events", _AGENT)(correlate_events),
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

    graph.set_entry_point("collect_readings")

    graph.add_conditional_edges(
        "collect_readings",
        _check_error,
        {"next": "check_thresholds", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_thresholds",
        _check_error,
        {"next": "correlate_events", "report": "report"},
    )
    graph.add_conditional_edges(
        "correlate_events",
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
