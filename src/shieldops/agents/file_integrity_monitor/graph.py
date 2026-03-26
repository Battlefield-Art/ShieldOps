"""LangGraph workflow for the File Integrity Monitor Agent."""

from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.file_integrity_monitor.models import (
    FileIntegrityMonitorState,
)
from shieldops.agents.file_integrity_monitor.nodes import (
    assess_impact,
    classify_changes,
    detect_changes,
    generate_report,
    respond,
    scan_baseline,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_respond(
    state: FileIntegrityMonitorState,
) -> str:
    """Route based on whether changes were detected.

    If changes exist, proceed to response. Otherwise
    skip to report.
    """
    if state.changes:
        return "respond"
    return "generate_report"


def create_file_integrity_monitor_graph() -> StateGraph[FileIntegrityMonitorState]:
    """Build the FIM Agent LangGraph workflow.

    Workflow:
        scan_baseline -> detect_changes -> classify_changes
            -> assess_impact
            -> [conditional: changes -> respond -> report]
            -> [conditional: no changes -> report]
            -> END
    """
    _agent = "file_integrity_monitor"
    graph: StateGraph[Any] = StateGraph(FileIntegrityMonitorState)

    # Add nodes with OTEL tracing spans
    graph.add_node(
        "scan_baseline",
        traced_node("fim.scan_baseline", _agent)(scan_baseline),
    )
    graph.add_node(
        "detect_changes",
        traced_node("fim.detect_changes", _agent)(detect_changes),
    )
    graph.add_node(
        "classify_changes",
        traced_node("fim.classify_changes", _agent)(classify_changes),
    )
    graph.add_node(
        "assess_impact",
        traced_node("fim.assess_impact", _agent)(assess_impact),
    )
    graph.add_node(
        "respond",
        traced_node("fim.respond", _agent)(respond),
    )
    graph.add_node(
        "generate_report",
        traced_node("fim.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("scan_baseline")
    graph.add_edge("scan_baseline", "detect_changes")
    graph.add_edge("detect_changes", "classify_changes")
    graph.add_edge("classify_changes", "assess_impact")
    graph.add_conditional_edges(
        "assess_impact",
        should_respond,
        {
            "respond": "respond",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("respond", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
