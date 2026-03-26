"""LangGraph workflow definition for the Cyber Recovery Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cyber_recovery.models import (
    CyberRecoveryState,
)
from shieldops.agents.cyber_recovery.nodes import (
    assess_damage,
    execute_recovery,
    report,
    select_recovery_points,
    validate_clean_room,
    verify_integrity,
)
from shieldops.agents.tracing import traced_node


def should_execute_recovery(
    state: CyberRecoveryState,
) -> str:
    """Route based on clean room validation results.

    If no clean recovery point exists, skip directly
    to report with failure status.
    """
    if state.error:
        return "report"
    if state.has_clean_point:
        return "execute_recovery"
    return "report"


def should_verify(
    state: CyberRecoveryState,
) -> str:
    """Route based on recovery execution results.

    If recovery failed, skip to report.
    """
    if state.error:
        return "report"
    if state.recovery_success:
        return "verify_integrity"
    return "report"


def create_cyber_recovery_graph() -> StateGraph[CyberRecoveryState]:
    """Build the Cyber Recovery Agent LangGraph workflow.

    Workflow:
        assess_damage -> select_recovery_points
            -> validate_clean_room
            -> [has_clean_point? -> execute_recovery]
            -> [success? -> verify_integrity]
            -> report
    """
    graph = StateGraph(CyberRecoveryState)

    _agent = "cyber_recovery"
    graph.add_node(
        "assess_damage",
        traced_node("cyber_recovery.assess_damage", _agent)(assess_damage),
    )
    graph.add_node(
        "select_recovery_points",
        traced_node(
            "cyber_recovery.select_recovery_points",
            _agent,
        )(select_recovery_points),
    )
    graph.add_node(
        "validate_clean_room",
        traced_node("cyber_recovery.validate_clean_room", _agent)(validate_clean_room),
    )
    graph.add_node(
        "execute_recovery",
        traced_node("cyber_recovery.execute_recovery", _agent)(execute_recovery),
    )
    graph.add_node(
        "verify_integrity",
        traced_node("cyber_recovery.verify_integrity", _agent)(verify_integrity),
    )
    graph.add_node(
        "report",
        traced_node("cyber_recovery.report", _agent)(report),
    )

    # Define edges
    graph.set_entry_point("assess_damage")
    graph.add_edge("assess_damage", "select_recovery_points")
    graph.add_edge("select_recovery_points", "validate_clean_room")
    graph.add_conditional_edges(
        "validate_clean_room",
        should_execute_recovery,
        {
            "execute_recovery": "execute_recovery",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "execute_recovery",
        should_verify,
        {
            "verify_integrity": "verify_integrity",
            "report": "report",
        },
    )
    graph.add_edge("verify_integrity", "report")
    graph.add_edge("report", END)

    return graph
