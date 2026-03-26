"""LangGraph workflow definition for the SOC Transformation Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.soc_transformation.models import (
    SOCTransformationState,
)
from shieldops.agents.soc_transformation.nodes import (
    assess_current_soc,
    design_target_architecture,
    execute_migration_steps,
    plan_migration,
    report,
    validate_transformation,
)
from shieldops.agents.tracing import traced_node


def has_migration_steps(
    state: SOCTransformationState,
) -> str:
    """Route based on whether migration plan has steps."""
    if state.migration_plan and state.migration_plan.steps:
        return "execute_migration_steps"
    return "report"


def should_validate(
    state: SOCTransformationState,
) -> str:
    """Route based on whether any steps completed."""
    if state.steps_completed > 0:
        return "validate_transformation"
    return "report"


def create_soc_transformation_graph() -> StateGraph[SOCTransformationState]:
    """Build the SOC Transformation LangGraph workflow.

    Workflow:
        assess_current_soc
        -> design_target_architecture
        -> plan_migration
        -> [has steps?]
            yes -> execute_migration_steps
                -> [steps completed?]
                    yes -> validate_transformation -> report -> END
                    no  -> report -> END
            no  -> report -> END
    """
    graph = StateGraph(SOCTransformationState)

    _agent = "soc_transformation"
    graph.add_node(
        "assess_current_soc",
        traced_node(
            "soc_transformation.assess_current_soc",
            _agent,
        )(assess_current_soc),
    )
    graph.add_node(
        "design_target_architecture",
        traced_node(
            "soc_transformation.design_target_architecture",
            _agent,
        )(design_target_architecture),
    )
    graph.add_node(
        "plan_migration",
        traced_node(
            "soc_transformation.plan_migration",
            _agent,
        )(plan_migration),
    )
    graph.add_node(
        "execute_migration_steps",
        traced_node(
            "soc_transformation.execute_migration_steps",
            _agent,
        )(execute_migration_steps),
    )
    graph.add_node(
        "validate_transformation",
        traced_node(
            "soc_transformation.validate_transformation",
            _agent,
        )(validate_transformation),
    )
    graph.add_node(
        "report",
        traced_node(
            "soc_transformation.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("assess_current_soc")
    graph.add_edge(
        "assess_current_soc",
        "design_target_architecture",
    )
    graph.add_edge(
        "design_target_architecture",
        "plan_migration",
    )
    graph.add_conditional_edges(
        "plan_migration",
        has_migration_steps,
        {
            "execute_migration_steps": ("execute_migration_steps"),
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "execute_migration_steps",
        should_validate,
        {
            "validate_transformation": ("validate_transformation"),
            "report": "report",
        },
    )
    graph.add_edge("validate_transformation", "report")
    graph.add_edge("report", END)

    return graph
