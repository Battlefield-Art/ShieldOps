"""LangGraph workflow for the Multi-Cloud Posture Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.multi_cloud_posture.models import (
    MultiCloudPostureState,
)
from shieldops.agents.multi_cloud_posture.nodes import (
    compare_posture,
    detect_gaps,
    generate_report,
    normalize_findings,
    recommend,
    scan_clouds,
)
from shieldops.agents.tracing import traced_node

_AGENT = "multi_cloud_posture"


def _should_normalize(
    state: MultiCloudPostureState,
) -> str:
    """Route after scan based on results."""
    if state.error:
        return "generate_report"
    if state.cloud_scans:
        return "normalize_findings"
    return "generate_report"


def _should_recommend(
    state: MultiCloudPostureState,
) -> str:
    """Route after gap detection."""
    if state.critical_gaps > 0:
        return "recommend"
    return "generate_report"


def create_multi_cloud_posture_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Multi-Cloud Posture LangGraph.

    Workflow:
        scan_clouds
          -> [has_scans?] -> normalize_findings
          -> compare_posture
          -> detect_gaps
          -> [has_critical?] -> recommend
          -> generate_report
    """
    graph = StateGraph(MultiCloudPostureState)

    graph.add_node(
        "scan_clouds",
        traced_node(
            f"{_AGENT}.scan_clouds",
            _AGENT,
        )(scan_clouds),
    )
    graph.add_node(
        "normalize_findings",
        traced_node(
            f"{_AGENT}.normalize_findings",
            _AGENT,
        )(normalize_findings),
    )
    graph.add_node(
        "compare_posture",
        traced_node(
            f"{_AGENT}.compare_posture",
            _AGENT,
        )(compare_posture),
    )
    graph.add_node(
        "detect_gaps",
        traced_node(
            f"{_AGENT}.detect_gaps",
            _AGENT,
        )(detect_gaps),
    )
    graph.add_node(
        "recommend",
        traced_node(
            f"{_AGENT}.recommend",
            _AGENT,
        )(recommend),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_clouds")
    graph.add_conditional_edges(
        "scan_clouds",
        _should_normalize,
        {
            "normalize_findings": "normalize_findings",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("normalize_findings", "compare_posture")
    graph.add_edge("compare_posture", "detect_gaps")
    graph.add_conditional_edges(
        "detect_gaps",
        _should_recommend,
        {
            "recommend": "recommend",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
