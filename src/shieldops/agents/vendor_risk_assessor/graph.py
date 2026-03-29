"""Vendor Risk Assessor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.vendor_risk_assessor.models import VendorRiskAssessorState
from shieldops.agents.vendor_risk_assessor.nodes import (
    classify_vendor,
    collect_data,
    evaluate_controls,
    recommend,
    report,
    score_risk,
)

_AGENT = "vendor_risk_assessor"


def _check_error(state: VendorRiskAssessorState) -> str:
    return "report" if state.error else "next"


def create_vendor_risk_assessor_graph() -> StateGraph:
    """Build the Vendor Risk Assessor workflow."""
    graph = StateGraph(VendorRiskAssessorState)

    graph.add_node(
        "collect_data",
        traced_node(f"{_AGENT}.collect_data", _AGENT)(collect_data),
    )
    graph.add_node(
        "score_risk",
        traced_node(f"{_AGENT}.score_risk", _AGENT)(score_risk),
    )
    graph.add_node(
        "evaluate_controls",
        traced_node(f"{_AGENT}.evaluate_controls", _AGENT)(evaluate_controls),
    )
    graph.add_node(
        "classify_vendor",
        traced_node(f"{_AGENT}.classify_vendor", _AGENT)(classify_vendor),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_data")

    graph.add_conditional_edges(
        "collect_data",
        _check_error,
        {"next": "score_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "score_risk",
        _check_error,
        {"next": "evaluate_controls", "report": "report"},
    )
    graph.add_conditional_edges(
        "evaluate_controls",
        _check_error,
        {"next": "classify_vendor", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_vendor",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
