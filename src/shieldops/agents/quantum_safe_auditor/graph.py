"""LangGraph workflow for the Quantum Safe Auditor Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.quantum_safe_auditor.models import (
    QuantumSafeAuditorState,
)
from shieldops.agents.quantum_safe_auditor.nodes import (
    assess_quantum_risk,
    generate_report,
    identify_vulnerable,
    inventory_crypto,
    plan_migration,
    track_progress,
)
from shieldops.agents.tracing import traced_node

_AGENT = "quantum_safe_auditor"


def _should_assess(
    state: QuantumSafeAuditorState,
) -> str:
    """Route after inventory based on results."""
    if state.error:
        return "generate_report"
    if state.crypto_inventory:
        return "assess_quantum_risk"
    return "generate_report"


def _should_plan(
    state: QuantumSafeAuditorState,
) -> str:
    """Route after vulnerability identification."""
    if state.vulnerable_count > 0:
        return "plan_migration"
    return "generate_report"


def create_quantum_safe_auditor_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Quantum Safe Auditor LangGraph.

    Workflow:
        inventory_crypto
          -> [has_assets?] -> assess_quantum_risk
          -> identify_vulnerable
          -> [has_vulnerable?] -> plan_migration
          -> track_progress
          -> generate_report
    """
    graph = StateGraph(QuantumSafeAuditorState)

    graph.add_node(
        "inventory_crypto",
        traced_node(
            f"{_AGENT}.inventory_crypto",
            _AGENT,
        )(inventory_crypto),
    )
    graph.add_node(
        "assess_quantum_risk",
        traced_node(
            f"{_AGENT}.assess_quantum_risk",
            _AGENT,
        )(assess_quantum_risk),
    )
    graph.add_node(
        "identify_vulnerable",
        traced_node(
            f"{_AGENT}.identify_vulnerable",
            _AGENT,
        )(identify_vulnerable),
    )
    graph.add_node(
        "plan_migration",
        traced_node(
            f"{_AGENT}.plan_migration",
            _AGENT,
        )(plan_migration),
    )
    graph.add_node(
        "track_progress",
        traced_node(
            f"{_AGENT}.track_progress",
            _AGENT,
        )(track_progress),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("inventory_crypto")
    graph.add_conditional_edges(
        "inventory_crypto",
        _should_assess,
        {
            "assess_quantum_risk": "assess_quantum_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_quantum_risk", "identify_vulnerable")
    graph.add_conditional_edges(
        "identify_vulnerable",
        _should_plan,
        {
            "plan_migration": "plan_migration",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("plan_migration", "track_progress")
    graph.add_edge("track_progress", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
