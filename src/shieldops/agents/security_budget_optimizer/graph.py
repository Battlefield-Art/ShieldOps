"""LangGraph workflow for the Security Budget Optimizer."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_budget_optimizer.models import (
    SecurityBudgetOptimizerState,
)
from shieldops.agents.security_budget_optimizer.nodes import (
    analyze_overlap,
    forecast_roi,
    generate_report,
    inventory_tools,
    measure_effectiveness,
    optimize_budget,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_budget_optimizer"


def _should_measure(
    state: SecurityBudgetOptimizerState,
) -> str:
    """Route after inventory based on results."""
    if state.error:
        return "generate_report"
    if state.tools_inventory:
        return "measure_effectiveness"
    return "generate_report"


def _should_forecast(
    state: SecurityBudgetOptimizerState,
) -> str:
    """Route after optimization."""
    if state.budget_allocations:
        return "forecast_roi"
    return "generate_report"


def create_security_budget_optimizer_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Budget Optimizer LangGraph.

    Workflow:
        inventory_tools
          -> [has_tools?] -> measure_effectiveness
          -> analyze_overlap
          -> optimize_budget
          -> [has_allocations?] -> forecast_roi
          -> generate_report
    """
    graph = StateGraph(SecurityBudgetOptimizerState)

    graph.add_node(
        "inventory_tools",
        traced_node(
            f"{_AGENT}.inventory_tools",
            _AGENT,
        )(inventory_tools),
    )
    graph.add_node(
        "measure_effectiveness",
        traced_node(
            f"{_AGENT}.measure_effectiveness",
            _AGENT,
        )(measure_effectiveness),
    )
    graph.add_node(
        "analyze_overlap",
        traced_node(
            f"{_AGENT}.analyze_overlap",
            _AGENT,
        )(analyze_overlap),
    )
    graph.add_node(
        "optimize_budget",
        traced_node(
            f"{_AGENT}.optimize_budget",
            _AGENT,
        )(optimize_budget),
    )
    graph.add_node(
        "forecast_roi",
        traced_node(
            f"{_AGENT}.forecast_roi",
            _AGENT,
        )(forecast_roi),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("inventory_tools")
    graph.add_conditional_edges(
        "inventory_tools",
        _should_measure,
        {
            "measure_effectiveness": "measure_effectiveness",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("measure_effectiveness", "analyze_overlap")
    graph.add_edge("analyze_overlap", "optimize_budget")
    graph.add_conditional_edges(
        "optimize_budget",
        _should_forecast,
        {
            "forecast_roi": "forecast_roi",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("forecast_roi", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
