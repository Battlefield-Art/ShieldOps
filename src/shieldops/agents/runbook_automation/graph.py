"""LangGraph workflow definition for the Runbook Automation Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.runbook_automation.models import RunbookAutomationState
from shieldops.agents.runbook_automation.nodes import (
    execute_steps,
    report,
    request_approval,
    select_runbook,
    validate_preconditions,
    verify_outcome,
)
from shieldops.agents.tracing import traced_node


def _route_after_select(state: RunbookAutomationState) -> str:
    """Route after runbook selection — abort on error."""
    if state.error:
        return "report"
    return "validate_preconditions"


def _route_after_validate(state: RunbookAutomationState) -> str:
    """Route after precondition validation — abort on blocking failure."""
    if state.error:
        return "report"
    return "request_approval"


def _route_after_approve(state: RunbookAutomationState) -> str:
    """Route after approval — abort if denied."""
    if state.error:
        return "report"
    return "execute_steps"


def _route_after_execute(state: RunbookAutomationState) -> str:
    """Route after execution — skip verification if rollback triggered."""
    if state.rollback_triggered:
        return "report"
    return "verify_outcome"


def create_runbook_automation_graph() -> StateGraph[RunbookAutomationState]:
    """Build the Runbook Automation Agent LangGraph workflow.

    Flow: select → validate → approve → execute → verify → report
    Conditional: errors/rollback short-circuit to report.
    """
    graph = StateGraph(RunbookAutomationState)

    _agent = "runbook_automation"
    graph.add_node(
        "select_runbook",
        traced_node("runbook_automation.select_runbook", _agent)(select_runbook),
    )
    graph.add_node(
        "validate_preconditions",
        traced_node("runbook_automation.validate_preconditions", _agent)(validate_preconditions),
    )
    graph.add_node(
        "request_approval",
        traced_node("runbook_automation.request_approval", _agent)(request_approval),
    )
    graph.add_node(
        "execute_steps",
        traced_node("runbook_automation.execute_steps", _agent)(execute_steps),
    )
    graph.add_node(
        "verify_outcome",
        traced_node("runbook_automation.verify_outcome", _agent)(verify_outcome),
    )
    graph.add_node(
        "report",
        traced_node("runbook_automation.report", _agent)(report),
    )

    # Entry
    graph.set_entry_point("select_runbook")

    # Conditional edges
    graph.add_conditional_edges(
        "select_runbook",
        _route_after_select,
        {"validate_preconditions": "validate_preconditions", "report": "report"},
    )
    graph.add_conditional_edges(
        "validate_preconditions",
        _route_after_validate,
        {"request_approval": "request_approval", "report": "report"},
    )
    graph.add_conditional_edges(
        "request_approval",
        _route_after_approve,
        {"execute_steps": "execute_steps", "report": "report"},
    )
    graph.add_conditional_edges(
        "execute_steps",
        _route_after_execute,
        {"verify_outcome": "verify_outcome", "report": "report"},
    )

    # Linear edges
    graph.add_edge("verify_outcome", "report")
    graph.add_edge("report", END)

    return graph
