"""Adversary Emulator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.adversary_emulator.models import AdversaryEmulatorState
from shieldops.agents.adversary_emulator.nodes import (
    execute_ttps,
    observe_defenses,
    plan_campaign,
    report,
    score,
    select_adversary,
)
from shieldops.agents.tracing import traced_node

_AGENT = "adversary_emulator"


def _check_error(state: AdversaryEmulatorState) -> str:
    return "report" if state.error else "next"


def create_adversary_emulator_graph() -> StateGraph:
    """Build the Adversary Emulator workflow."""
    graph = StateGraph(AdversaryEmulatorState)

    graph.add_node(
        "select_adversary",
        traced_node(f"{_AGENT}.select_adversary", _AGENT)(select_adversary),
    )
    graph.add_node(
        "plan_campaign",
        traced_node(f"{_AGENT}.plan_campaign", _AGENT)(plan_campaign),
    )
    graph.add_node(
        "execute_ttps",
        traced_node(f"{_AGENT}.execute_ttps", _AGENT)(execute_ttps),
    )
    graph.add_node(
        "observe_defenses",
        traced_node(f"{_AGENT}.observe_defenses", _AGENT)(observe_defenses),
    )
    graph.add_node(
        "score",
        traced_node(f"{_AGENT}.score", _AGENT)(score),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("select_adversary")

    graph.add_conditional_edges(
        "select_adversary",
        _check_error,
        {"next": "plan_campaign", "report": "report"},
    )
    graph.add_conditional_edges(
        "plan_campaign",
        _check_error,
        {"next": "execute_ttps", "report": "report"},
    )
    graph.add_conditional_edges(
        "execute_ttps",
        _check_error,
        {"next": "observe_defenses", "report": "report"},
    )
    graph.add_conditional_edges(
        "observe_defenses",
        _check_error,
        {"next": "score", "report": "report"},
    )
    graph.add_edge("score", "report")
    graph.add_edge("report", END)

    return graph
