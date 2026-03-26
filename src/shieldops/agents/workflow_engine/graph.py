"""LangGraph workflow definition for the Workflow Engine Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.workflow_engine.models import WorkflowEngineState
from shieldops.agents.workflow_engine.nodes import (
    check_gates,
    execute_steps,
    finalize_workflow,
    load_workflow,
    report_workflow,
    validate_workflow,
)


def should_continue_after_load(state: WorkflowEngineState) -> str:
    """Route after loading — skip to finalize on error."""
    if state.error:
        return "finalize_workflow"
    return "validate_workflow"


def should_continue_after_validate(state: WorkflowEngineState) -> str:
    """Route after validation — skip to finalize on failure."""
    if not state.validation_passed:
        return "finalize_workflow"
    return "execute_steps"


def create_workflow_engine_graph() -> StateGraph[WorkflowEngineState]:
    """Build the Workflow Engine Agent LangGraph workflow."""
    graph = StateGraph(WorkflowEngineState)

    _agent = "workflow_engine"
    graph.add_node(
        "load_workflow",
        traced_node("workflow_engine.load_workflow", _agent)(load_workflow),
    )
    graph.add_node(
        "validate_workflow",
        traced_node("workflow_engine.validate_workflow", _agent)(validate_workflow),
    )
    graph.add_node(
        "execute_steps",
        traced_node("workflow_engine.execute_steps", _agent)(execute_steps),
    )
    graph.add_node(
        "check_gates",
        traced_node("workflow_engine.check_gates", _agent)(check_gates),
    )
    graph.add_node(
        "finalize_workflow",
        traced_node("workflow_engine.finalize_workflow", _agent)(finalize_workflow),
    )
    graph.add_node(
        "report_workflow",
        traced_node("workflow_engine.report_workflow", _agent)(report_workflow),
    )

    graph.set_entry_point("load_workflow")
    graph.add_conditional_edges(
        "load_workflow",
        should_continue_after_load,
        {
            "validate_workflow": "validate_workflow",
            "finalize_workflow": "finalize_workflow",
        },
    )
    graph.add_conditional_edges(
        "validate_workflow",
        should_continue_after_validate,
        {
            "execute_steps": "execute_steps",
            "finalize_workflow": "finalize_workflow",
        },
    )
    graph.add_edge("execute_steps", "check_gates")
    graph.add_edge("check_gates", "finalize_workflow")
    graph.add_edge("finalize_workflow", "report_workflow")
    graph.add_edge("report_workflow", END)

    return graph
