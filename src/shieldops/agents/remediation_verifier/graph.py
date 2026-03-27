"""LangGraph workflow for the Remediation Verifier Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.remediation_verifier.models import (
    RemediationVerifierState,
)
from shieldops.agents.remediation_verifier.nodes import (
    assess_results,
    collect_remediations,
    design_verification_tests,
    execute_tests,
    flag_regressions,
    generate_report,
)
from shieldops.agents.tracing import traced_node


def route_after_assess(
    state: RemediationVerifierState,
) -> str:
    """Route: flag regressions if any found."""
    if state.still_vulnerable_count > 0:
        return "flag_regressions"
    return "generate_report"


def build_graph() -> StateGraph:
    """Build the Remediation Verifier LangGraph."""
    _a = "remediation_verifier"
    graph = StateGraph(RemediationVerifierState)

    graph.add_node(
        "collect_remediations",
        traced_node("remver.collect", _a)(collect_remediations),
    )
    graph.add_node(
        "design_verification_tests",
        traced_node("remver.design", _a)(design_verification_tests),
    )
    graph.add_node(
        "execute_tests",
        traced_node("remver.execute", _a)(execute_tests),
    )
    graph.add_node(
        "assess_results",
        traced_node("remver.assess", _a)(assess_results),
    )
    graph.add_node(
        "flag_regressions",
        traced_node("remver.flag", _a)(flag_regressions),
    )
    graph.add_node(
        "generate_report",
        traced_node("remver.report", _a)(generate_report),
    )

    graph.set_entry_point("collect_remediations")
    graph.add_edge(
        "collect_remediations",
        "design_verification_tests",
    )
    graph.add_edge("design_verification_tests", "execute_tests")
    graph.add_edge("execute_tests", "assess_results")
    graph.add_conditional_edges(
        "assess_results",
        route_after_assess,
        {
            "flag_regressions": "flag_regressions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("flag_regressions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_remediation_verifier_graph(
    **clients: object,
) -> StateGraph:
    """Factory for Remediation Verifier graph."""
    return build_graph()
