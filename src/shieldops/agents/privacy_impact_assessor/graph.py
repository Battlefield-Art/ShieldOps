"""Privacy Impact Assessor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.privacy_impact_assessor.models import PrivacyImpactAssessorState
from shieldops.agents.privacy_impact_assessor.nodes import (
    assess_risks,
    document,
    identify_mitigations,
    identify_processing,
    map_data_flows,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "privacy_impact_assessor"


def _check_error(state: PrivacyImpactAssessorState) -> str:
    return "report" if state.error else "next"


def create_privacy_impact_assessor_graph() -> StateGraph:
    """Build the Privacy Impact Assessor workflow."""
    graph = StateGraph(PrivacyImpactAssessorState)

    graph.add_node(
        "identify_processing",
        traced_node(f"{_AGENT}.identify_processing", _AGENT)(identify_processing),
    )
    graph.add_node(
        "map_data_flows",
        traced_node(f"{_AGENT}.map_data_flows", _AGENT)(map_data_flows),
    )
    graph.add_node(
        "assess_risks",
        traced_node(f"{_AGENT}.assess_risks", _AGENT)(assess_risks),
    )
    graph.add_node(
        "identify_mitigations",
        traced_node(f"{_AGENT}.identify_mitigations", _AGENT)(identify_mitigations),
    )
    graph.add_node(
        "document",
        traced_node(f"{_AGENT}.document", _AGENT)(document),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("identify_processing")

    graph.add_conditional_edges(
        "identify_processing",
        _check_error,
        {"next": "map_data_flows", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_data_flows",
        _check_error,
        {"next": "assess_risks", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_risks",
        _check_error,
        {"next": "identify_mitigations", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_mitigations",
        _check_error,
        {"next": "document", "report": "report"},
    )
    graph.add_edge("document", "report")
    graph.add_edge("report", END)

    return graph
