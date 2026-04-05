"""LangGraph workflow for the Forensic Evidence Chain Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.forensic_evidence_chain.models import (
    ForensicEvidenceChainState,
)
from shieldops.agents.forensic_evidence_chain.nodes import (
    chain_custody,
    collect_evidence,
    generate_report,
    hash_artifacts,
    package_for_legal,
    validate_integrity,
)
from shieldops.agents.tracing import traced_node

_AGENT = "forensic_evidence_chain"


def _should_chain_custody(
    state: ForensicEvidenceChainState,
) -> str:
    """Route after hashing artifacts."""
    if state.error:
        return "generate_report"
    if state.artifact_hashes:
        return "chain_custody"
    return "generate_report"


def _should_package(
    state: ForensicEvidenceChainState,
) -> str:
    """Route after integrity validation."""
    if state.integrity_results:
        return "package_for_legal"
    return "generate_report"


def create_forensic_evidence_chain_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Forensic Evidence Chain LangGraph.

    Workflow:
        collect_evidence -> hash_artifacts
          -> [has_hashes?] -> chain_custody -> validate_integrity
          -> [has_results?] -> package_for_legal -> generate_report
    """
    graph = StateGraph(ForensicEvidenceChainState)

    graph.add_node(
        "collect_evidence",
        traced_node(f"{_AGENT}.collect_evidence", _AGENT)(collect_evidence),
    )
    graph.add_node(
        "hash_artifacts",
        traced_node(f"{_AGENT}.hash_artifacts", _AGENT)(hash_artifacts),
    )
    graph.add_node(
        "chain_custody",
        traced_node(f"{_AGENT}.chain_custody", _AGENT)(chain_custody),
    )
    graph.add_node(
        "validate_integrity",
        traced_node(f"{_AGENT}.validate_integrity", _AGENT)(validate_integrity),
    )
    graph.add_node(
        "package_for_legal",
        traced_node(f"{_AGENT}.package_for_legal", _AGENT)(package_for_legal),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_evidence")
    graph.add_edge("collect_evidence", "hash_artifacts")
    graph.add_conditional_edges(
        "hash_artifacts",
        _should_chain_custody,
        {
            "chain_custody": "chain_custody",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("chain_custody", "validate_integrity")
    graph.add_conditional_edges(
        "validate_integrity",
        _should_package,
        {
            "package_for_legal": "package_for_legal",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("package_for_legal", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
