"""LangGraph workflow definition for the Incident Simulator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_simulator.models import (
    IncidentSimulatorState,
)
from shieldops.agents.incident_simulator.nodes import (
    debrief,
    design_scenario,
    inject_events,
    observe_response,
    report,
    score_performance,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_simulator"


def _route_after_design(
    state: IncidentSimulatorState,
) -> str:
    """Route after design: proceed or jump to report on error."""
    if state.error:
        return "report"
    return "inject_events"


def create_incident_simulator_graph() -> StateGraph[IncidentSimulatorState]:
    """Build the Incident Simulator Agent LangGraph workflow.

    Workflow:
        design_scenario -> [conditional: inject_events OR report]
        inject_events -> observe_response -> score_performance
            -> debrief -> report -> END
    """
    graph = StateGraph(IncidentSimulatorState)

    graph.add_node(
        "design_scenario",
        traced_node("simulator.design_scenario", _AGENT)(design_scenario),
    )
    graph.add_node(
        "inject_events",
        traced_node("simulator.inject_events", _AGENT)(inject_events),
    )
    graph.add_node(
        "observe_response",
        traced_node("simulator.observe_response", _AGENT)(observe_response),
    )
    graph.add_node(
        "score_performance",
        traced_node("simulator.score_performance", _AGENT)(score_performance),
    )
    graph.add_node(
        "debrief",
        traced_node("simulator.debrief", _AGENT)(debrief),
    )
    graph.add_node(
        "report",
        traced_node("simulator.report", _AGENT)(report),
    )

    # Define edges
    graph.set_entry_point("design_scenario")
    graph.add_conditional_edges(
        "design_scenario",
        _route_after_design,
        {
            "inject_events": "inject_events",
            "report": "report",
        },
    )
    graph.add_edge("inject_events", "observe_response")
    graph.add_edge("observe_response", "score_performance")
    graph.add_edge("score_performance", "debrief")
    graph.add_edge("debrief", "report")
    graph.add_edge("report", END)

    return graph
