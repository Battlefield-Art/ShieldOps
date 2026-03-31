"""LangGraph workflow definition for the Cloud Snapshot
Analyzer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_snapshot_analyzer.models import (
    CloudSnapshotAnalyzerState,
)
from shieldops.agents.cloud_snapshot_analyzer.nodes import (
    analyze_config,
    assess_risk,
    check_encryption,
    detect_exposure,
    discover_snapshots,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_snapshot_analyzer"


def _should_assess_risk(
    state: CloudSnapshotAnalyzerState,
) -> str:
    """Route after exposure detection: assess risk if
    findings exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    has_findings = len(state.encryption_findings) > 0 and len(state.exposure_findings) > 0
    return "assess_risk" if has_findings else "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Snapshot Analyzer LangGraph
    workflow.

    Workflow:
        discover_snapshots -> analyze_config
            -> check_encryption -> detect_exposure
            -> [findings? -> assess_risk]
            -> generate_report -> END
    """
    graph = StateGraph(CloudSnapshotAnalyzerState)

    graph.add_node(
        "discover_snapshots",
        traced_node(f"{_AGENT}.discover_snapshots", _AGENT)(discover_snapshots),
    )
    graph.add_node(
        "analyze_config",
        traced_node(f"{_AGENT}.analyze_config", _AGENT)(analyze_config),
    )
    graph.add_node(
        "check_encryption",
        traced_node(f"{_AGENT}.check_encryption", _AGENT)(check_encryption),
    )
    graph.add_node(
        "detect_exposure",
        traced_node(f"{_AGENT}.detect_exposure", _AGENT)(detect_exposure),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_snapshots")
    graph.add_edge("discover_snapshots", "analyze_config")
    graph.add_edge("analyze_config", "check_encryption")
    graph.add_edge("check_encryption", "detect_exposure")
    graph.add_conditional_edges(
        "detect_exposure",
        _should_assess_risk,
        {
            "assess_risk": "assess_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_snapshot_analyzer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Snapshot Analyzer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
