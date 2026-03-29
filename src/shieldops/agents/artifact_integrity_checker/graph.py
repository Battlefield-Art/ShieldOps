"""Artifact Integrity Checker Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.artifact_integrity_checker.models import ArtifactIntegrityCheckerState
from shieldops.agents.artifact_integrity_checker.nodes import (
    assess,
    check_checksums,
    collect_artifacts,
    report,
    validate_provenance,
    verify_signatures,
)
from shieldops.agents.tracing import traced_node

_AGENT = "artifact_integrity_checker"


def _check_error(state: ArtifactIntegrityCheckerState) -> str:
    return "report" if state.error else "next"


def create_artifact_integrity_checker_graph() -> StateGraph:
    """Build the Artifact Integrity Checker workflow."""
    graph = StateGraph(ArtifactIntegrityCheckerState)

    graph.add_node(
        "collect_artifacts",
        traced_node(f"{_AGENT}.collect_artifacts", _AGENT)(collect_artifacts),
    )
    graph.add_node(
        "verify_signatures",
        traced_node(f"{_AGENT}.verify_signatures", _AGENT)(verify_signatures),
    )
    graph.add_node(
        "check_checksums",
        traced_node(f"{_AGENT}.check_checksums", _AGENT)(check_checksums),
    )
    graph.add_node(
        "validate_provenance",
        traced_node(f"{_AGENT}.validate_provenance", _AGENT)(validate_provenance),
    )
    graph.add_node(
        "assess",
        traced_node(f"{_AGENT}.assess", _AGENT)(assess),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_artifacts")

    graph.add_conditional_edges(
        "collect_artifacts",
        _check_error,
        {"next": "verify_signatures", "report": "report"},
    )
    graph.add_conditional_edges(
        "verify_signatures",
        _check_error,
        {"next": "check_checksums", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_checksums",
        _check_error,
        {"next": "validate_provenance", "report": "report"},
    )
    graph.add_conditional_edges(
        "validate_provenance",
        _check_error,
        {"next": "assess", "report": "report"},
    )
    graph.add_edge("assess", "report")
    graph.add_edge("report", END)

    return graph
