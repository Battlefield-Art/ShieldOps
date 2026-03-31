"""LangGraph workflow definition for the Backup Integrity
Verifier Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.backup_integrity_verifier.models import (
    BackupIntegrityVerifierState,
)
from shieldops.agents.backup_integrity_verifier.nodes import (
    assess_coverage,
    check_encryption,
    discover_backups,
    generate_report,
    test_restore,
    verify_integrity,
)
from shieldops.agents.tracing import traced_node

_AGENT = "backup_integrity_verifier"


def _should_test_restore(
    state: BackupIntegrityVerifierState,
) -> str:
    """Route after encryption check: test restore if
    backups exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_backups > 0:
        return "test_restore"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Backup Integrity Verifier LangGraph
    workflow.

    Workflow:
        discover_backups -> verify_integrity
            -> check_encryption
            -> [backups? -> test_restore -> assess_coverage]
            -> generate_report -> END
    """
    graph = StateGraph(BackupIntegrityVerifierState)

    graph.add_node(
        "discover_backups",
        traced_node(f"{_AGENT}.discover_backups", _AGENT)(discover_backups),
    )
    graph.add_node(
        "verify_integrity",
        traced_node(f"{_AGENT}.verify_integrity", _AGENT)(verify_integrity),
    )
    graph.add_node(
        "check_encryption",
        traced_node(f"{_AGENT}.check_encryption", _AGENT)(check_encryption),
    )
    graph.add_node(
        "test_restore",
        traced_node(f"{_AGENT}.test_restore", _AGENT)(test_restore),
    )
    graph.add_node(
        "assess_coverage",
        traced_node(f"{_AGENT}.assess_coverage", _AGENT)(assess_coverage),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_backups")
    graph.add_edge("discover_backups", "verify_integrity")
    graph.add_edge("verify_integrity", "check_encryption")
    graph.add_conditional_edges(
        "check_encryption",
        _should_test_restore,
        {
            "test_restore": "test_restore",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("test_restore", "assess_coverage")
    graph.add_edge("assess_coverage", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_backup_integrity_verifier_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Backup Integrity Verifier
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
