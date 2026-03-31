"""LangGraph workflow definition for the Security Chaos
Tester Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_chaos_tester.models import (
    SecurityChaosState,
)
from shieldops.agents.security_chaos_tester.nodes import (
    assess_resilience,
    define_experiment,
    document_findings,
    generate_report,
    inject_fault,
    observe_behavior,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_chaos_tester"


def _should_document(
    state: SecurityChaosState,
) -> str:
    """Route after resilience assessment: document if
    findings exist or on error, else skip to report."""
    if state.error:
        return "generate_report"
    if state.critical_failures > 0:
        return "document_findings"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Chaos Tester LangGraph
    workflow.

    Workflow:
        define_experiment -> inject_fault
            -> observe_behavior -> assess_resilience
            -> [critical? -> document_findings]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityChaosState)

    graph.add_node(
        "define_experiment",
        traced_node(f"{_AGENT}.define_experiment", _AGENT)(define_experiment),
    )
    graph.add_node(
        "inject_fault",
        traced_node(f"{_AGENT}.inject_fault", _AGENT)(inject_fault),
    )
    graph.add_node(
        "observe_behavior",
        traced_node(f"{_AGENT}.observe_behavior", _AGENT)(observe_behavior),
    )
    graph.add_node(
        "assess_resilience",
        traced_node(f"{_AGENT}.assess_resilience", _AGENT)(assess_resilience),
    )
    graph.add_node(
        "document_findings",
        traced_node(f"{_AGENT}.document_findings", _AGENT)(document_findings),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("define_experiment")
    graph.add_edge("define_experiment", "inject_fault")
    graph.add_edge("inject_fault", "observe_behavior")
    graph.add_edge("observe_behavior", "assess_resilience")
    graph.add_conditional_edges(
        "assess_resilience",
        _should_document,
        {
            "document_findings": "document_findings",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("document_findings", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_chaos_tester_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Chaos Tester
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
