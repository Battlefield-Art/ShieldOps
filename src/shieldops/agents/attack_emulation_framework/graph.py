"""LangGraph workflow definition for the Attack
Emulation Framework Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.attack_emulation_framework.models import (
    AttackEmulationState,
)
from shieldops.agents.attack_emulation_framework.nodes import (
    build_campaign,
    execute_techniques,
    generate_gaps,
    generate_report,
    measure_detection,
    select_adversary,
)
from shieldops.agents.tracing import traced_node

_AGENT = "attack_emulation_framework"


def _should_analyze_gaps(
    state: AttackEmulationState,
) -> str:
    """Route after detection measurement: analyze gaps
    if techniques were executed, else report."""
    if state.error:
        return "generate_report"
    if state.techniques_executed > 0:
        return "generate_gaps"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Attack Emulation Framework workflow.

    Workflow:
        select_adversary -> build_campaign
            -> execute_techniques -> measure_detection
            -> [executed? -> generate_gaps]
            -> generate_report -> END
    """
    graph = StateGraph(AttackEmulationState)

    graph.add_node(
        "select_adversary",
        traced_node(f"{_AGENT}.select_adversary", _AGENT)(select_adversary),
    )
    graph.add_node(
        "build_campaign",
        traced_node(f"{_AGENT}.build_campaign", _AGENT)(build_campaign),
    )
    graph.add_node(
        "execute_techniques",
        traced_node(f"{_AGENT}.execute_techniques", _AGENT)(execute_techniques),
    )
    graph.add_node(
        "measure_detection",
        traced_node(f"{_AGENT}.measure_detection", _AGENT)(measure_detection),
    )
    graph.add_node(
        "generate_gaps",
        traced_node(f"{_AGENT}.generate_gaps", _AGENT)(generate_gaps),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("select_adversary")
    graph.add_edge("select_adversary", "build_campaign")
    graph.add_edge("build_campaign", "execute_techniques")
    graph.add_edge("execute_techniques", "measure_detection")
    graph.add_conditional_edges(
        "measure_detection",
        _should_analyze_gaps,
        {
            "generate_gaps": "generate_gaps",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_gaps", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_attack_emulation_framework_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Attack Emulation Framework
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
