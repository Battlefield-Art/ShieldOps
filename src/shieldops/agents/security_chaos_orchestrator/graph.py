"""LangGraph workflow for the Security Chaos Orchestrator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_chaos_orchestrator.models import (
    SecurityChaosOrchestratorState,
)
from shieldops.agents.security_chaos_orchestrator.nodes import (
    analyze_resilience,
    define_blast_radius,
    generate_report,
    inject_failures,
    observe_behavior,
    plan_experiments,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_chaos_orchestrator"


def _should_inject(
    state: SecurityChaosOrchestratorState,
) -> str:
    """Route after blast radius definition."""
    if state.error:
        return "generate_report"
    if state.blast_radii:
        return "inject_failures"
    return "generate_report"


def _should_analyze(
    state: SecurityChaosOrchestratorState,
) -> str:
    """Route after observation."""
    if state.observations:
        return "analyze_resilience"
    return "generate_report"


def create_security_chaos_orchestrator_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Chaos Orchestrator LangGraph.

    Workflow:
        plan_experiments -> define_blast_radius
          -> [has_radii?] -> inject_failures -> observe_behavior
          -> [has_obs?] -> analyze_resilience -> generate_report
    """
    graph = StateGraph(SecurityChaosOrchestratorState)

    graph.add_node(
        "plan_experiments",
        traced_node(f"{_AGENT}.plan_experiments", _AGENT)(plan_experiments),
    )
    graph.add_node(
        "define_blast_radius",
        traced_node(f"{_AGENT}.define_blast_radius", _AGENT)(define_blast_radius),
    )
    graph.add_node(
        "inject_failures",
        traced_node(f"{_AGENT}.inject_failures", _AGENT)(inject_failures),
    )
    graph.add_node(
        "observe_behavior",
        traced_node(f"{_AGENT}.observe_behavior", _AGENT)(observe_behavior),
    )
    graph.add_node(
        "analyze_resilience",
        traced_node(f"{_AGENT}.analyze_resilience", _AGENT)(analyze_resilience),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("plan_experiments")
    graph.add_edge("plan_experiments", "define_blast_radius")
    graph.add_conditional_edges(
        "define_blast_radius",
        _should_inject,
        {
            "inject_failures": "inject_failures",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("inject_failures", "observe_behavior")
    graph.add_conditional_edges(
        "observe_behavior",
        _should_analyze,
        {
            "analyze_resilience": "analyze_resilience",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_resilience", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
