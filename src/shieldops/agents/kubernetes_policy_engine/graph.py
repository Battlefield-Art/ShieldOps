"""LangGraph workflow definition for the Kubernetes
Policy Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.kubernetes_policy_engine.models import (
    KubernetesPolicyEngineState,
)
from shieldops.agents.kubernetes_policy_engine.nodes import (
    check_standards,
    detect_violations,
    enforce_policies,
    evaluate_policies,
    generate_report,
    scan_resources,
)
from shieldops.agents.tracing import traced_node

_AGENT = "kubernetes_policy_engine"


def _should_enforce(
    state: KubernetesPolicyEngineState,
) -> str:
    """Route after violation detection: enforce if
    violations exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_violations > 0:
        return "enforce_policies"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Kubernetes Policy Engine LangGraph
    workflow.

    Workflow:
        scan_resources -> evaluate_policies
            -> check_standards -> detect_violations
            -> [violations? -> enforce_policies]
            -> generate_report -> END
    """
    graph = StateGraph(KubernetesPolicyEngineState)

    graph.add_node(
        "scan_resources",
        traced_node(f"{_AGENT}.scan_resources", _AGENT)(scan_resources),
    )
    graph.add_node(
        "evaluate_policies",
        traced_node(f"{_AGENT}.evaluate_policies", _AGENT)(evaluate_policies),
    )
    graph.add_node(
        "check_standards",
        traced_node(f"{_AGENT}.check_standards", _AGENT)(check_standards),
    )
    graph.add_node(
        "detect_violations",
        traced_node(f"{_AGENT}.detect_violations", _AGENT)(detect_violations),
    )
    graph.add_node(
        "enforce_policies",
        traced_node(f"{_AGENT}.enforce_policies", _AGENT)(enforce_policies),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_resources")
    graph.add_edge("scan_resources", "evaluate_policies")
    graph.add_edge("evaluate_policies", "check_standards")
    graph.add_edge("check_standards", "detect_violations")
    graph.add_conditional_edges(
        "detect_violations",
        _should_enforce,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_kubernetes_policy_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Kubernetes Policy Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
