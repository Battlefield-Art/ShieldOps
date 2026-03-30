"""LangGraph workflow for the Compliance Evidence Collector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.compliance_evidence_collector.models import (
    ComplianceEvidenceCollectorState,
)
from shieldops.agents.compliance_evidence_collector.nodes import (
    collect_evidence,
    generate_compliance_report,
    generate_report,
    identify_controls,
    map_frameworks,
    validate_evidence,
)
from shieldops.agents.tracing import traced_node

_AGENT = "compliance_evidence_collector"


def _should_collect(
    state: ComplianceEvidenceCollectorState,
) -> str:
    """Route after control identification based on results."""
    if state.error:
        return "generate_report"
    if state.control_requirements:
        return "collect_evidence"
    return "generate_report"


def _should_generate_report(
    state: ComplianceEvidenceCollectorState,
) -> str:
    """Route after framework mapping based on coverage."""
    if state.coverage_pct > 50.0:
        return "generate_compliance_report"
    return "generate_report"


def create_compliance_evidence_collector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Evidence Collector LangGraph.

    Workflow:
        identify_controls
          -> [has_controls?] -> collect_evidence
          -> validate_evidence
          -> map_frameworks
          -> [good_coverage?] -> generate_compliance_report
          -> generate_report
    """
    graph = StateGraph(ComplianceEvidenceCollectorState)

    graph.add_node(
        "identify_controls",
        traced_node(
            f"{_AGENT}.identify_controls",
            _AGENT,
        )(identify_controls),
    )
    graph.add_node(
        "collect_evidence",
        traced_node(
            f"{_AGENT}.collect_evidence",
            _AGENT,
        )(collect_evidence),
    )
    graph.add_node(
        "validate_evidence",
        traced_node(
            f"{_AGENT}.validate_evidence",
            _AGENT,
        )(validate_evidence),
    )
    graph.add_node(
        "map_frameworks",
        traced_node(
            f"{_AGENT}.map_frameworks",
            _AGENT,
        )(map_frameworks),
    )
    graph.add_node(
        "generate_compliance_report",
        traced_node(
            f"{_AGENT}.generate_compliance_report",
            _AGENT,
        )(generate_compliance_report),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("identify_controls")
    graph.add_conditional_edges(
        "identify_controls",
        _should_collect,
        {
            "collect_evidence": "collect_evidence",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("collect_evidence", "validate_evidence")
    graph.add_edge("validate_evidence", "map_frameworks")
    graph.add_conditional_edges(
        "map_frameworks",
        _should_generate_report,
        {
            "generate_compliance_report": "generate_compliance_report",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_compliance_report", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
