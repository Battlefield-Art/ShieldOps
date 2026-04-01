"""LangGraph workflow for the Security Policy Optimizer Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_policy_optimizer.models import (
    SecurityPolicyOptimizerState,
)
from shieldops.agents.security_policy_optimizer.nodes import (
    analyze_effectiveness,
    apply_changes,
    collect_policies,
    generate_report,
    identify_optimizations,
    validate_changes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_policy_optimizer"


def _should_optimize(
    state: SecurityPolicyOptimizerState,
) -> str:
    """Route after effectiveness analysis."""
    if state.error:
        return "generate_report"
    if state.effectiveness:
        return "identify_optimizations"
    return "generate_report"


def _should_validate(
    state: SecurityPolicyOptimizerState,
) -> str:
    """Route after applying changes."""
    applied = [c for c in state.changes if c.get("applied", False)]
    if applied:
        return "validate_changes"
    return "generate_report"


def create_security_policy_optimizer_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Policy Optimizer LangGraph.

    Workflow:
        collect_policies -> analyze_effectiveness
          -> [has_metrics?] -> identify_optimizations -> apply_changes
          -> [has_applied?] -> validate_changes -> generate_report
    """
    graph = StateGraph(SecurityPolicyOptimizerState)

    graph.add_node(
        "collect_policies",
        traced_node(f"{_AGENT}.collect_policies", _AGENT)(collect_policies),
    )
    graph.add_node(
        "analyze_effectiveness",
        traced_node(f"{_AGENT}.analyze_effectiveness", _AGENT)(analyze_effectiveness),
    )
    graph.add_node(
        "identify_optimizations",
        traced_node(f"{_AGENT}.identify_optimizations", _AGENT)(identify_optimizations),
    )
    graph.add_node(
        "apply_changes",
        traced_node(f"{_AGENT}.apply_changes", _AGENT)(apply_changes),
    )
    graph.add_node(
        "validate_changes",
        traced_node(f"{_AGENT}.validate_changes", _AGENT)(validate_changes),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_policies")
    graph.add_edge("collect_policies", "analyze_effectiveness")
    graph.add_conditional_edges(
        "analyze_effectiveness",
        _should_optimize,
        {
            "identify_optimizations": "identify_optimizations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("identify_optimizations", "apply_changes")
    graph.add_conditional_edges(
        "apply_changes",
        _should_validate,
        {
            "validate_changes": "validate_changes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_changes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
