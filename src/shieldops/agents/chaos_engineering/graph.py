"""LangGraph workflow definition for the Chaos Engineering Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.chaos_engineering.models import ChaosEngineeringState
from shieldops.agents.chaos_engineering.nodes import (
    abort_experiment,
    analyze_results,
    generate_report,
    inject_fault,
    observe_impact,
    plan_experiment,
    validate_safety,
)
from shieldops.agents.tracing import traced_node


def route_after_safety(state: ChaosEngineeringState) -> str:
    """Route based on safety check results.

    If any blocking safety check failed, abort the experiment.
    Otherwise proceed to fault injection.
    """
    if state.error:
        return "abort_experiment"
    if not state.safety_passed:
        return "abort_experiment"
    return "inject_fault"


def create_chaos_engineering_graph() -> StateGraph[ChaosEngineeringState]:
    """Build the Chaos Engineering Agent LangGraph workflow.

    Workflow:
        plan_experiment → validate_safety
            → [conditional: inject_fault OR abort_experiment]
        inject_fault → observe_impact → analyze_results → generate_report → END
        abort_experiment → generate_report → END
    """
    graph = StateGraph(ChaosEngineeringState)

    _agent = "chaos_engineering"

    graph.add_node(
        "plan_experiment",
        traced_node("chaos.plan_experiment", _agent)(plan_experiment),
    )
    graph.add_node(
        "validate_safety",
        traced_node("chaos.validate_safety", _agent)(validate_safety),
    )
    graph.add_node(
        "inject_fault",
        traced_node("chaos.inject_fault", _agent)(inject_fault),
    )
    graph.add_node(
        "observe_impact",
        traced_node("chaos.observe_impact", _agent)(observe_impact),
    )
    graph.add_node(
        "analyze_results",
        traced_node("chaos.analyze_results", _agent)(analyze_results),
    )
    graph.add_node(
        "generate_report",
        traced_node("chaos.generate_report", _agent)(generate_report),
    )
    graph.add_node(
        "abort_experiment",
        traced_node("chaos.abort_experiment", _agent)(abort_experiment),
    )

    # Define edges
    graph.set_entry_point("plan_experiment")
    graph.add_edge("plan_experiment", "validate_safety")
    graph.add_conditional_edges(
        "validate_safety",
        route_after_safety,
        {
            "inject_fault": "inject_fault",
            "abort_experiment": "abort_experiment",
        },
    )
    graph.add_edge("inject_fault", "observe_impact")
    graph.add_edge("observe_impact", "analyze_results")
    graph.add_edge("analyze_results", "generate_report")
    graph.add_edge("abort_experiment", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
