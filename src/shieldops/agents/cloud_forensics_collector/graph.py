"""LangGraph workflow definition for the Cloud Forensics
Collector Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_forensics_collector.models import (
    CloudForensicsCollectorState,
)
from shieldops.agents.cloud_forensics_collector.nodes import (
    analyze_evidence,
    capture_snapshots,
    collect_logs,
    generate_report,
    identify_scope,
    preserve_evidence,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_forensics_collector"


def _should_analyze(
    state: CloudForensicsCollectorState,
) -> str:
    """Route after preservation: analyze if evidence
    exists, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_evidence > 0:
        return "analyze_evidence"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Forensics Collector LangGraph
    workflow.

    Workflow:
        identify_scope -> collect_logs
            -> capture_snapshots -> preserve_evidence
            -> [evidence? -> analyze_evidence]
            -> generate_report -> END
    """
    graph = StateGraph(CloudForensicsCollectorState)

    graph.add_node(
        "identify_scope",
        traced_node(f"{_AGENT}.identify_scope", _AGENT)(identify_scope),
    )
    graph.add_node(
        "collect_logs",
        traced_node(f"{_AGENT}.collect_logs", _AGENT)(collect_logs),
    )
    graph.add_node(
        "capture_snapshots",
        traced_node(f"{_AGENT}.capture_snapshots", _AGENT)(capture_snapshots),
    )
    graph.add_node(
        "preserve_evidence",
        traced_node(f"{_AGENT}.preserve_evidence", _AGENT)(preserve_evidence),
    )
    graph.add_node(
        "analyze_evidence",
        traced_node(f"{_AGENT}.analyze_evidence", _AGENT)(analyze_evidence),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("identify_scope")
    graph.add_edge("identify_scope", "collect_logs")
    graph.add_edge("collect_logs", "capture_snapshots")
    graph.add_edge("capture_snapshots", "preserve_evidence")
    graph.add_conditional_edges(
        "preserve_evidence",
        _should_analyze,
        {
            "analyze_evidence": "analyze_evidence",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_evidence", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_forensics_collector_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Forensics Collector
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
