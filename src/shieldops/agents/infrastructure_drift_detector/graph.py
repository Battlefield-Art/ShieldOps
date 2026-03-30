"""Infrastructure Drift Detector — LangGraph definition."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import InfrastructureDriftDetectorState
from .nodes import (
    classify_changes,
    compare_baseline,
    detect_drift,
    remediate_drift,
    report,
    scan_infrastructure,
)

logger = structlog.get_logger()

_AGENT = "infrastructure_drift_detector"


def _check_error(
    state: InfrastructureDriftDetectorState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_infrastructure_drift_detector_graph() -> StateGraph[InfrastructureDriftDetectorState]:
    """Build the Infrastructure Drift Detector graph.

    Flow:
        scan_infrastructure -> compare_baseline
        -> detect_drift -> classify_changes
        -> remediate_drift -> report
    """
    graph = StateGraph(InfrastructureDriftDetectorState)

    graph.add_node(
        "scan_infrastructure",
        traced_node(
            "idd.scan_infrastructure",
            _AGENT,
        )(scan_infrastructure),
    )
    graph.add_node(
        "compare_baseline",
        traced_node(
            "idd.compare_baseline",
            _AGENT,
        )(compare_baseline),
    )
    graph.add_node(
        "detect_drift",
        traced_node(
            "idd.detect_drift",
            _AGENT,
        )(detect_drift),
    )
    graph.add_node(
        "classify_changes",
        traced_node(
            "idd.classify_changes",
            _AGENT,
        )(classify_changes),
    )
    graph.add_node(
        "remediate_drift",
        traced_node(
            "idd.remediate_drift",
            _AGENT,
        )(remediate_drift),
    )
    graph.add_node(
        "report",
        traced_node(
            "idd.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("scan_infrastructure")

    graph.add_conditional_edges(
        "scan_infrastructure",
        _check_error,
        {"report": "report", "next": "compare_baseline"},
    )
    graph.add_conditional_edges(
        "compare_baseline",
        _check_error,
        {"report": "report", "next": "detect_drift"},
    )
    graph.add_conditional_edges(
        "detect_drift",
        _check_error,
        {"report": "report", "next": "classify_changes"},
    )
    graph.add_conditional_edges(
        "classify_changes",
        _check_error,
        {
            "report": "report",
            "next": "remediate_drift",
        },
    )
    graph.add_edge("remediate_drift", "report")
    graph.add_edge("report", END)

    return graph
