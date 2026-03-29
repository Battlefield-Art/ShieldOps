"""Orphan Account Detector Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.orphan_account_detector.models import OrphanAccountDetectorState
from shieldops.agents.orphan_account_detector.nodes import (
    classify_risk,
    cross_reference_hr,
    identify_orphans,
    remediate,
    report,
    scan_accounts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "orphan_account_detector"


def _check_error(state: OrphanAccountDetectorState) -> str:
    return "report" if state.error else "next"


def create_orphan_account_detector_graph() -> StateGraph:
    """Build the Orphan Account Detector workflow."""
    graph = StateGraph(OrphanAccountDetectorState)

    graph.add_node(
        "scan_accounts",
        traced_node(f"{_AGENT}.scan_accounts", _AGENT)(scan_accounts),
    )
    graph.add_node(
        "cross_reference_hr",
        traced_node(f"{_AGENT}.cross_reference_hr", _AGENT)(cross_reference_hr),
    )
    graph.add_node(
        "identify_orphans",
        traced_node(f"{_AGENT}.identify_orphans", _AGENT)(identify_orphans),
    )
    graph.add_node(
        "classify_risk",
        traced_node(f"{_AGENT}.classify_risk", _AGENT)(classify_risk),
    )
    graph.add_node(
        "remediate",
        traced_node(f"{_AGENT}.remediate", _AGENT)(remediate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("scan_accounts")

    graph.add_conditional_edges(
        "scan_accounts",
        _check_error,
        {"next": "cross_reference_hr", "report": "report"},
    )
    graph.add_conditional_edges(
        "cross_reference_hr",
        _check_error,
        {"next": "identify_orphans", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_orphans",
        _check_error,
        {"next": "classify_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_risk",
        _check_error,
        {"next": "remediate", "report": "report"},
    )
    graph.add_edge("remediate", "report")
    graph.add_edge("report", END)

    return graph
