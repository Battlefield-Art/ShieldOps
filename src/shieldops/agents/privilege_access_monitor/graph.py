"""LangGraph workflow definition for the Privilege
Access Monitor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.privilege_access_monitor.models import (
    PrivilegeAccessMonitorState,
)
from shieldops.agents.privilege_access_monitor.nodes import (
    assess_risk,
    audit_sessions,
    detect_abuse,
    discover_accounts,
    enforce_jit,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "privilege_access_monitor"


def _should_enforce(
    state: PrivilegeAccessMonitorState,
) -> str:
    """Route after risk assessment: enforce JIT if
    high-risk accounts exist, otherwise report."""
    if state.error:
        return "generate_report"
    if state.high_risk_count > 0:
        return "enforce_jit"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Privilege Access Monitor LangGraph
    workflow.

    Workflow:
        discover_accounts -> audit_sessions
            -> detect_abuse -> assess_risk
            -> [high_risk? -> enforce_jit]
            -> generate_report -> END
    """
    graph = StateGraph(PrivilegeAccessMonitorState)

    graph.add_node(
        "discover_accounts",
        traced_node(f"{_AGENT}.discover_accounts", _AGENT)(discover_accounts),
    )
    graph.add_node(
        "audit_sessions",
        traced_node(f"{_AGENT}.audit_sessions", _AGENT)(audit_sessions),
    )
    graph.add_node(
        "detect_abuse",
        traced_node(f"{_AGENT}.detect_abuse", _AGENT)(detect_abuse),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "enforce_jit",
        traced_node(f"{_AGENT}.enforce_jit", _AGENT)(enforce_jit),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_accounts")
    graph.add_edge("discover_accounts", "audit_sessions")
    graph.add_edge("audit_sessions", "detect_abuse")
    graph.add_edge("detect_abuse", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _should_enforce,
        {
            "enforce_jit": "enforce_jit",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_jit", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_privilege_access_monitor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Privilege Access Monitor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
