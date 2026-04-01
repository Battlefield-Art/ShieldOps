"""LangGraph workflow definition for Fleet Coordination Engine."""

from langgraph.graph import END, StateGraph

from shieldops.agents.fleet_coordination_engine.models import (
    FleetCoordinationEngineState,
)
from shieldops.agents.fleet_coordination_engine.nodes import (
    assess_health,
    discover_agents,
    dispatch_work,
    generate_report,
    monitor_progress,
    plan_routing,
)
from shieldops.agents.tracing import traced_node

# ── Routing Functions ───────────────────────────────────


def should_assess(
    state: FleetCoordinationEngineState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "generate_report"
    if state.total_agents > 0:
        return "assess_health"
    return "generate_report"


def should_dispatch(
    state: FleetCoordinationEngineState,
) -> str:
    """Route after routing plan based on assignments."""
    if state.routing_plans:
        return "dispatch_work"
    return "generate_report"


# ── Graph Builder ───────────────────────────────────────


def create_fleet_coordination_engine_graph() -> StateGraph[FleetCoordinationEngineState]:
    """Build the Fleet Coordination Engine workflow.

    Workflow:
        discover_agents
          -> [has_agents? -> assess_health]
          -> plan_routing
          -> [has_plans? -> dispatch_work]
          -> monitor_progress
          -> generate_report
    """
    graph = StateGraph(FleetCoordinationEngineState)

    _agent = "fleet_coordination_engine"
    graph.add_node(
        "discover_agents",
        traced_node(
            "fce.discover_agents",
            _agent,
        )(discover_agents),
    )
    graph.add_node(
        "assess_health",
        traced_node(
            "fce.assess_health",
            _agent,
        )(assess_health),
    )
    graph.add_node(
        "plan_routing",
        traced_node(
            "fce.plan_routing",
            _agent,
        )(plan_routing),
    )
    graph.add_node(
        "dispatch_work",
        traced_node(
            "fce.dispatch_work",
            _agent,
        )(dispatch_work),
    )
    graph.add_node(
        "monitor_progress",
        traced_node(
            "fce.monitor_progress",
            _agent,
        )(monitor_progress),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "fce.generate_report",
            _agent,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("discover_agents")
    graph.add_conditional_edges(
        "discover_agents",
        should_assess,
        {
            "assess_health": "assess_health",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_health", "plan_routing")
    graph.add_conditional_edges(
        "plan_routing",
        should_dispatch,
        {
            "dispatch_work": "dispatch_work",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("dispatch_work", "monitor_progress")
    graph.add_edge("monitor_progress", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
