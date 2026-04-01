"""Compliance Evidence Generator — LangGraph StateGraph definition."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.compliance_evidence_generator.models import (
    ComplianceEvidenceGeneratorState,
)
from shieldops.agents.compliance_evidence_generator.nodes import (
    collect_evidence,
    generate_report,
    identify_controls,
    identify_gaps,
    package_evidence,
    validate_evidence,
)
from shieldops.agents.tracing import traced_node

_AGENT = "compliance_evidence_generator"


def _should_validate(
    state: ComplianceEvidenceGeneratorState,
) -> str:
    """Route after evidence collection."""
    if state.error:
        return "generate_report"
    if state.evidence:
        return "validate_evidence"
    return "generate_report"


def _should_package(
    state: ComplianceEvidenceGeneratorState,
) -> str:
    """Route after gap identification."""
    if state.error:
        return "generate_report"
    if state.controls:
        return "package_evidence"
    return "generate_report"


def create_compliance_evidence_generator_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Evidence Generator LangGraph.

    Workflow:
        identify_controls -> collect_evidence
          -> [has_evidence?] -> validate_evidence -> identify_gaps
          -> [has_controls?] -> package_evidence -> generate_report
    """
    graph = StateGraph(ComplianceEvidenceGeneratorState)

    graph.add_node(
        "identify_controls",
        traced_node(f"{_AGENT}.identify_controls", _AGENT)(identify_controls),
    )
    graph.add_node(
        "collect_evidence",
        traced_node(f"{_AGENT}.collect_evidence", _AGENT)(collect_evidence),
    )
    graph.add_node(
        "validate_evidence",
        traced_node(f"{_AGENT}.validate_evidence", _AGENT)(validate_evidence),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "package_evidence",
        traced_node(f"{_AGENT}.package_evidence", _AGENT)(package_evidence),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("identify_controls")
    graph.add_edge("identify_controls", "collect_evidence")
    graph.add_conditional_edges(
        "collect_evidence",
        _should_validate,
        {
            "validate_evidence": "validate_evidence",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_evidence", "identify_gaps")
    graph.add_conditional_edges(
        "identify_gaps",
        _should_package,
        {
            "package_evidence": "package_evidence",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("package_evidence", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
