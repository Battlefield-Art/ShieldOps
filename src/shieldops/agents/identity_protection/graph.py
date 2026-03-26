"""LangGraph workflow for the Identity Protection Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.identity_protection.models import (
    IdentityProtectionState,
)
from shieldops.agents.identity_protection.nodes import (
    analyze_attack_patterns,
    collect_identity_signals,
    detect_threats,
    report,
    respond_to_threats,
    verify_containment,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def has_active_threats(
    state: IdentityProtectionState,
) -> str:
    """Route based on whether active threats exist."""
    if state.error:
        return "report"
    critical_or_high = any(t.severity in ("critical", "high") for t in state.threats_detected)
    has_patterns = len(state.attack_patterns) > 0
    if critical_or_high or has_patterns:
        return "respond_to_threats"
    return "report"


def create_identity_protection_graph() -> StateGraph[IdentityProtectionState]:
    """Build the Identity Protection LangGraph workflow.

    Workflow:
        collect_identity_signals -> detect_threats
            -> analyze_attack_patterns
            -> [conditional: respond_to_threats OR report]
            -> verify_containment -> report -> END
    """
    graph = StateGraph(IdentityProtectionState)

    _agent = "identity_protection"
    graph.add_node(
        "collect_identity_signals",
        traced_node(
            "identity_protection.collect_signals",
            _agent,
        )(collect_identity_signals),
    )
    graph.add_node(
        "detect_threats",
        traced_node(
            "identity_protection.detect_threats",
            _agent,
        )(detect_threats),
    )
    graph.add_node(
        "analyze_attack_patterns",
        traced_node(
            "identity_protection.analyze_patterns",
            _agent,
        )(analyze_attack_patterns),
    )
    graph.add_node(
        "respond_to_threats",
        traced_node(
            "identity_protection.respond",
            _agent,
        )(respond_to_threats),
    )
    graph.add_node(
        "verify_containment",
        traced_node(
            "identity_protection.verify",
            _agent,
        )(verify_containment),
    )
    graph.add_node(
        "report",
        traced_node(
            "identity_protection.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("collect_identity_signals")
    graph.add_edge(
        "collect_identity_signals",
        "detect_threats",
    )
    graph.add_edge(
        "detect_threats",
        "analyze_attack_patterns",
    )
    graph.add_conditional_edges(
        "analyze_attack_patterns",
        has_active_threats,
        {
            "respond_to_threats": "respond_to_threats",
            "report": "report",
        },
    )
    graph.add_edge(
        "respond_to_threats",
        "verify_containment",
    )
    graph.add_edge("verify_containment", "report")
    graph.add_edge("report", END)

    return graph
