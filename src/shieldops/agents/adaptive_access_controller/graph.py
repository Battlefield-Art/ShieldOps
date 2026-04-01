"""LangGraph workflow for the Adaptive Access Controller Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.adaptive_access_controller.models import (
    AdaptiveAccessControllerState,
)
from shieldops.agents.adaptive_access_controller.nodes import (
    adjust_permissions,
    assess_context,
    audit_decisions,
    enforce_access,
    evaluate_risk,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "adaptive_access_controller"


def _should_enforce(
    state: AdaptiveAccessControllerState,
) -> str:
    """Route after permission adjustment."""
    if state.error:
        return "generate_report"
    if state.permission_adjustments:
        return "enforce_access"
    return "generate_report"


def _should_audit(
    state: AdaptiveAccessControllerState,
) -> str:
    """Route after enforcement."""
    if state.enforcement_results:
        return "audit_decisions"
    return "generate_report"


def create_adaptive_access_controller_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Adaptive Access Controller LangGraph.

    Workflow:
        assess_context -> evaluate_risk -> adjust_permissions
          -> [has_adjustments?] -> enforce_access
          -> [has_results?] -> audit_decisions -> generate_report
    """
    graph = StateGraph(AdaptiveAccessControllerState)

    graph.add_node(
        "assess_context",
        traced_node(
            f"{_AGENT}.assess_context",
            _AGENT,
        )(assess_context),
    )
    graph.add_node(
        "evaluate_risk",
        traced_node(
            f"{_AGENT}.evaluate_risk",
            _AGENT,
        )(evaluate_risk),
    )
    graph.add_node(
        "adjust_permissions",
        traced_node(
            f"{_AGENT}.adjust_permissions",
            _AGENT,
        )(adjust_permissions),
    )
    graph.add_node(
        "enforce_access",
        traced_node(
            f"{_AGENT}.enforce_access",
            _AGENT,
        )(enforce_access),
    )
    graph.add_node(
        "audit_decisions",
        traced_node(
            f"{_AGENT}.audit_decisions",
            _AGENT,
        )(audit_decisions),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    graph.set_entry_point("assess_context")
    graph.add_edge("assess_context", "evaluate_risk")
    graph.add_edge("evaluate_risk", "adjust_permissions")
    graph.add_conditional_edges(
        "adjust_permissions",
        _should_enforce,
        {
            "enforce_access": "enforce_access",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "enforce_access",
        _should_audit,
        {
            "audit_decisions": "audit_decisions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("audit_decisions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
