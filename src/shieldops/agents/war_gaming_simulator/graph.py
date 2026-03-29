"""War Gaming Simulator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.war_gaming_simulator.models import WarGamingSimulatorState
from shieldops.agents.war_gaming_simulator.nodes import (
    assign_teams,
    design_scenario,
    execute_rounds,
    observe,
    report,
    score,
)

_AGENT = "war_gaming_simulator"


def _check_error(state: WarGamingSimulatorState) -> str:
    return "report" if state.error else "next"


def create_war_gaming_simulator_graph() -> StateGraph:
    """Build the War Gaming Simulator workflow."""
    graph = StateGraph(WarGamingSimulatorState)

    graph.add_node(
        "design_scenario",
        traced_node(f"{_AGENT}.design_scenario", _AGENT)(design_scenario),
    )
    graph.add_node(
        "assign_teams",
        traced_node(f"{_AGENT}.assign_teams", _AGENT)(assign_teams),
    )
    graph.add_node(
        "execute_rounds",
        traced_node(f"{_AGENT}.execute_rounds", _AGENT)(execute_rounds),
    )
    graph.add_node(
        "observe",
        traced_node(f"{_AGENT}.observe", _AGENT)(observe),
    )
    graph.add_node(
        "score",
        traced_node(f"{_AGENT}.score", _AGENT)(score),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("design_scenario")

    graph.add_conditional_edges(
        "design_scenario",
        _check_error,
        {"next": "assign_teams", "report": "report"},
    )
    graph.add_conditional_edges(
        "assign_teams",
        _check_error,
        {"next": "execute_rounds", "report": "report"},
    )
    graph.add_conditional_edges(
        "execute_rounds",
        _check_error,
        {"next": "observe", "report": "report"},
    )
    graph.add_conditional_edges(
        "observe",
        _check_error,
        {"next": "score", "report": "report"},
    )
    graph.add_edge("score", "report")
    graph.add_edge("report", END)

    return graph
