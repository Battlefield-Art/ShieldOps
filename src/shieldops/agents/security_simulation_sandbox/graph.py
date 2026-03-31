"""LangGraph workflow definition for the Security
Simulation Sandbox Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_simulation_sandbox.models import (
    SecuritySimulationSandboxState,
)
from shieldops.agents.security_simulation_sandbox.nodes import (
    analyze,
    collect_results,
    configure_scenario,
    execute_test,
    generate_report,
    provision_sandbox,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_simulation_sandbox"


def _should_analyze(
    state: SecuritySimulationSandboxState,
) -> str:
    """Route after collection: analyze if results exist
    or skip to report on error."""
    if state.error:
        return "generate_report"
    if len(state.test_results) > 0:
        return "analyze"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Simulation Sandbox LangGraph
    workflow.

    Workflow:
        provision_sandbox -> configure_scenario
            -> execute_test -> collect_results
            -> [results? -> analyze]
            -> generate_report -> END
    """
    graph = StateGraph(SecuritySimulationSandboxState)

    graph.add_node(
        "provision_sandbox",
        traced_node(f"{_AGENT}.provision_sandbox", _AGENT)(provision_sandbox),
    )
    graph.add_node(
        "configure_scenario",
        traced_node(f"{_AGENT}.configure_scenario", _AGENT)(configure_scenario),
    )
    graph.add_node(
        "execute_test",
        traced_node(f"{_AGENT}.execute_test", _AGENT)(execute_test),
    )
    graph.add_node(
        "collect_results",
        traced_node(f"{_AGENT}.collect_results", _AGENT)(collect_results),
    )
    graph.add_node(
        "analyze",
        traced_node(f"{_AGENT}.analyze", _AGENT)(analyze),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("provision_sandbox")
    graph.add_edge("provision_sandbox", "configure_scenario")
    graph.add_edge("configure_scenario", "execute_test")
    graph.add_edge("execute_test", "collect_results")
    graph.add_conditional_edges(
        "collect_results",
        _should_analyze,
        {
            "analyze": "analyze",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_simulation_sandbox_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Simulation Sandbox
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
