"""LangGraph workflow definition for the Compliance Workflow Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.compliance_workflow.models import (
    ComplianceWorkflowState,
)
from shieldops.agents.compliance_workflow.nodes import (
    collect_evidence,
    identify_controls,
    identify_gaps,
    remediate,
    report,
    test_controls,
)
from shieldops.agents.tracing import traced_node

_AGENT = "compliance_workflow"


def create_compliance_workflow_graph() -> StateGraph:
    """Build the Compliance Workflow Agent LangGraph workflow.

    Workflow:
        identify_controls -> collect_evidence -> test_controls
        -> identify_gaps -> remediate -> report -> END

    Error edges route directly to report for graceful
    degradation.
    """
    graph = StateGraph(ComplianceWorkflowState)

    graph.add_node(
        "identify_controls",
        traced_node(
            "compliance_workflow.identify_controls",
            _AGENT,
        )(identify_controls),
    )
    graph.add_node(
        "collect_evidence",
        traced_node(
            "compliance_workflow.collect_evidence",
            _AGENT,
        )(collect_evidence),
    )
    graph.add_node(
        "test_controls",
        traced_node(
            "compliance_workflow.test_controls",
            _AGENT,
        )(test_controls),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(
            "compliance_workflow.identify_gaps",
            _AGENT,
        )(identify_gaps),
    )
    graph.add_node(
        "remediate",
        traced_node(
            "compliance_workflow.remediate",
            _AGENT,
        )(remediate),
    )
    graph.add_node(
        "report",
        traced_node(
            "compliance_workflow.report",
            _AGENT,
        )(report),
    )

    # Linear pipeline with error edges to report
    graph.set_entry_point("identify_controls")

    def _route_or_report(
        field: str,
        next_node: str,
    ):  # noqa: ANN202
        """Return a router that checks for errors."""

        def _router(
            state: ComplianceWorkflowState,
        ) -> str:
            if state.error:
                return "report"
            return next_node

        return _router

    graph.add_conditional_edges(
        "identify_controls",
        _route_or_report("error", "collect_evidence"),
        {
            "collect_evidence": "collect_evidence",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "collect_evidence",
        _route_or_report("error", "test_controls"),
        {
            "test_controls": "test_controls",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "test_controls",
        _route_or_report("error", "identify_gaps"),
        {
            "identify_gaps": "identify_gaps",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "identify_gaps",
        _route_or_report("error", "remediate"),
        {"remediate": "remediate", "report": "report"},
    )
    graph.add_edge("remediate", "report")
    graph.add_edge("report", END)

    return graph
