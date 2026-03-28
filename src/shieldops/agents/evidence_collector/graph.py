"""LangGraph workflow definition for the Evidence Collector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.evidence_collector.models import (
    EvidenceCollectorState,
)
from shieldops.agents.evidence_collector.nodes import (
    chain_of_custody,
    collect_artifacts,
    hash_verify,
    identify_sources,
    package_evidence,
    report,
)
from shieldops.agents.tracing import traced_node


def _should_continue(
    state: EvidenceCollectorState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "report"
    return "continue"


def create_evidence_collector_graph() -> StateGraph[EvidenceCollectorState]:
    """Build the Evidence Collector LangGraph workflow.

    Workflow:
        identify_sources -> collect_artifacts -> hash_verify
            -> chain_of_custody -> package_evidence -> report
            -> END
        Any error routes directly to report.
    """
    graph = StateGraph(EvidenceCollectorState)

    _agent = "evidence_collector"
    graph.add_node(
        "identify_sources",
        traced_node(
            "evidence_collector.identify_sources",
            _agent,
        )(identify_sources),
    )
    graph.add_node(
        "collect_artifacts",
        traced_node(
            "evidence_collector.collect_artifacts",
            _agent,
        )(collect_artifacts),
    )
    graph.add_node(
        "hash_verify",
        traced_node(
            "evidence_collector.hash_verify",
            _agent,
        )(hash_verify),
    )
    graph.add_node(
        "chain_of_custody",
        traced_node(
            "evidence_collector.chain_of_custody",
            _agent,
        )(chain_of_custody),
    )
    graph.add_node(
        "package_evidence",
        traced_node(
            "evidence_collector.package_evidence",
            _agent,
        )(package_evidence),
    )
    graph.add_node(
        "report",
        traced_node(
            "evidence_collector.report",
            _agent,
        )(report),
    )

    # Entry point
    graph.set_entry_point("identify_sources")

    # Linear flow with error routing
    graph.add_conditional_edges(
        "identify_sources",
        _should_continue,
        {
            "continue": "collect_artifacts",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "collect_artifacts",
        _should_continue,
        {
            "continue": "hash_verify",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "hash_verify",
        _should_continue,
        {
            "continue": "chain_of_custody",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "chain_of_custody",
        _should_continue,
        {
            "continue": "package_evidence",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "package_evidence",
        _should_continue,
        {
            "continue": "report",
            "report": "report",
        },
    )
    graph.add_edge("report", END)

    return graph
