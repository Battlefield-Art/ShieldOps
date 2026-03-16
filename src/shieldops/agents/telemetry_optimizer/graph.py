"""LangGraph workflow definition for the Telemetry Optimizer Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.telemetry_optimizer.models import (
    TelemetryOptimizerState,
)
from shieldops.agents.telemetry_optimizer.nodes import (
    analyze_pipeline,
    identify_waste,
    propose_optimizations,
    run_experiments,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def has_more_experiments(state: TelemetryOptimizerState) -> str:
    """Decide whether to loop back for more proposals or finish.

    Loops back to propose if:
    - There are waste items without corresponding proposals
    - Confidence score is below threshold and we haven't exhausted iterations

    Otherwise, ends the workflow.
    """
    proposed_services = {p.target_service for p in state.proposals}
    remaining_waste = [w for w in state.waste_items if w.service_name not in proposed_services]

    if remaining_waste and state.confidence_score < 0.8:
        return "propose_optimizations"
    return END


def create_telemetry_optimizer_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Telemetry Optimizer Agent LangGraph workflow.

    Workflow:
        analyze_pipeline → identify_waste → propose_optimizations
            → run_experiments → conditional(more_experiments? propose : END)
    """
    graph: StateGraph = StateGraph(TelemetryOptimizerState)  # type: ignore[type-arg]

    # Add nodes (wrapped with OTEL tracing spans)
    _agent = "telemetry_optimizer"
    graph.add_node(
        "analyze_pipeline",
        traced_node("telemetry_optimizer.analyze_pipeline", _agent)(analyze_pipeline),
    )
    graph.add_node(
        "identify_waste",
        traced_node("telemetry_optimizer.identify_waste", _agent)(identify_waste),
    )
    graph.add_node(
        "propose_optimizations",
        traced_node("telemetry_optimizer.propose_optimizations", _agent)(propose_optimizations),
    )
    graph.add_node(
        "run_experiments",
        traced_node("telemetry_optimizer.run_experiments", _agent)(run_experiments),
    )

    # Define edges
    graph.set_entry_point("analyze_pipeline")
    graph.add_edge("analyze_pipeline", "identify_waste")
    graph.add_edge("identify_waste", "propose_optimizations")
    graph.add_edge("propose_optimizations", "run_experiments")
    graph.add_conditional_edges(
        "run_experiments",
        has_more_experiments,
        {
            "propose_optimizations": "propose_optimizations",
            END: END,
        },
    )

    return graph
