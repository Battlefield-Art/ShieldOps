"""LangGraph workflow definition for the Threat
Simulation Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_simulation_engine.models import (
    ThreatSimulationEngineState,
)
from shieldops.agents.threat_simulation_engine.nodes import (
    deploy_attack,
    evaluate_response,
    generate_gaps,
    generate_report,
    monitor_detection,
    plan_scenario,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_simulation_engine"


def _should_generate_gaps(
    state: ThreatSimulationEngineState,
) -> str:
    """Route after evaluation: generate gaps if attacks
    exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_attacks > 0:
        return "generate_gaps"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Simulation Engine LangGraph
    workflow.

    Workflow:
        plan_scenario -> deploy_attack
            -> monitor_detection -> evaluate_response
            -> [attacks? -> generate_gaps]
            -> generate_report -> END
    """
    graph = StateGraph(ThreatSimulationEngineState)

    graph.add_node(
        "plan_scenario",
        traced_node(f"{_AGENT}.plan_scenario", _AGENT)(plan_scenario),
    )
    graph.add_node(
        "deploy_attack",
        traced_node(f"{_AGENT}.deploy_attack", _AGENT)(deploy_attack),
    )
    graph.add_node(
        "monitor_detection",
        traced_node(f"{_AGENT}.monitor_detection", _AGENT)(monitor_detection),
    )
    graph.add_node(
        "evaluate_response",
        traced_node(f"{_AGENT}.evaluate_response", _AGENT)(evaluate_response),
    )
    graph.add_node(
        "generate_gaps",
        traced_node(f"{_AGENT}.generate_gaps", _AGENT)(generate_gaps),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("plan_scenario")
    graph.add_edge("plan_scenario", "deploy_attack")
    graph.add_edge("deploy_attack", "monitor_detection")
    graph.add_edge("monitor_detection", "evaluate_response")
    graph.add_conditional_edges(
        "evaluate_response",
        _should_generate_gaps,
        {
            "generate_gaps": "generate_gaps",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_gaps", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_threat_simulation_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Threat Simulation Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
