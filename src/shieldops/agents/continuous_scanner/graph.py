"""LangGraph workflow for the Continuous Scanner Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.continuous_scanner.models import (
    ContinuousScannerState,
)
from shieldops.agents.continuous_scanner.nodes import (
    check_due_scans,
    collect_results,
    dispatch_scans,
    generate_report,
    load_schedule,
    monitor_progress,
)
from shieldops.agents.tracing import traced_node

_AGENT = "continuous_scanner"


def _has_due_scans(
    state: ContinuousScannerState,
) -> str:
    """Route based on whether scans are due."""
    if state.error:
        return END
    if not state.due_scans:
        return "generate_report"
    return "dispatch_scans"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Continuous Scanner StateGraph.

    Workflow:
        load_schedule -> check_due_scans
        -> [no due? -> generate_report -> END]
        -> dispatch_scans -> monitor_progress
        -> collect_results -> generate_report -> END
    """
    graph = StateGraph(ContinuousScannerState)

    graph.add_node(
        "load_schedule",
        traced_node(f"{_AGENT}.load_schedule", _AGENT)(load_schedule),
    )
    graph.add_node(
        "check_due_scans",
        traced_node(f"{_AGENT}.check_due_scans", _AGENT)(check_due_scans),
    )
    graph.add_node(
        "dispatch_scans",
        traced_node(f"{_AGENT}.dispatch_scans", _AGENT)(dispatch_scans),
    )
    graph.add_node(
        "monitor_progress",
        traced_node(f"{_AGENT}.monitor_progress", _AGENT)(monitor_progress),
    )
    graph.add_node(
        "collect_results",
        traced_node(f"{_AGENT}.collect_results", _AGENT)(collect_results),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("load_schedule")
    graph.add_edge("load_schedule", "check_due_scans")
    graph.add_conditional_edges(
        "check_due_scans",
        _has_due_scans,
        {
            "dispatch_scans": "dispatch_scans",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("dispatch_scans", "monitor_progress")
    graph.add_edge("monitor_progress", "collect_results")
    graph.add_edge("collect_results", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_continuous_scanner_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create the Continuous Scanner graph."""
    return build_graph()
