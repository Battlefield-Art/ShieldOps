"""Compliance Automation Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.compliance_automation_engine.models import (
    ComplianceAutomationEngineState,
)
from shieldops.agents.compliance_automation_engine.nodes import (
    assess_gaps,
    collect_evidence,
    discover_controls,
    generate_attestation,
    report,
    test_controls,
)
from shieldops.agents.tracing import traced_node

_AGENT = "compliance_automation_engine"


def _check_error(state: ComplianceAutomationEngineState) -> str:
    return "report" if state.error else "next"


def create_compliance_automation_engine_graph() -> StateGraph:
    """Build the Compliance Automation Engine workflow."""
    graph = StateGraph(ComplianceAutomationEngineState)

    graph.add_node(
        "discover_controls",
        traced_node(f"{_AGENT}.discover_controls", _AGENT)(discover_controls),
    )
    graph.add_node(
        "test_controls",
        traced_node(f"{_AGENT}.test_controls", _AGENT)(test_controls),
    )
    graph.add_node(
        "collect_evidence",
        traced_node(f"{_AGENT}.collect_evidence", _AGENT)(collect_evidence),
    )
    graph.add_node(
        "assess_gaps",
        traced_node(f"{_AGENT}.assess_gaps", _AGENT)(assess_gaps),
    )
    graph.add_node(
        "generate_attestation",
        traced_node(f"{_AGENT}.generate_attestation", _AGENT)(generate_attestation),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_controls")

    graph.add_conditional_edges(
        "discover_controls",
        _check_error,
        {"next": "test_controls", "report": "report"},
    )
    graph.add_conditional_edges(
        "test_controls",
        _check_error,
        {"next": "collect_evidence", "report": "report"},
    )
    graph.add_conditional_edges(
        "collect_evidence",
        _check_error,
        {"next": "assess_gaps", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_gaps",
        _check_error,
        {"next": "generate_attestation", "report": "report"},
    )
    graph.add_edge("generate_attestation", "report")
    graph.add_edge("report", END)

    return graph
