"""LangGraph workflow definition for the Security Automation Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.security_automation.models import SecurityAutomationState
from shieldops.agents.security_automation.nodes import (
    execute_response,
    select_playbook,
    triage_alerts,
    validate_and_learn,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_continue_after_triage(state: SecurityAutomationState) -> str:
    """Route based on triage results — skip to END if no alerts pass."""
    if state.triaged_alerts:
        return "select_playbook"
    return END


def create_security_automation_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Automation Agent LangGraph workflow.

    Workflow:
        triage_alerts
            → [conditional: select_playbook OR END]
            → execute_response
            → validate_and_learn
            → END
    """
    graph = StateGraph(SecurityAutomationState)

    _agent = "security_automation"

    # Add nodes (wrapped with OTEL tracing spans)
    graph.add_node(
        "triage_alerts",
        traced_node("security_automation.triage_alerts", _agent)(triage_alerts),
    )
    graph.add_node(
        "select_playbook",
        traced_node("security_automation.select_playbook", _agent)(select_playbook),
    )
    graph.add_node(
        "execute_response",
        traced_node("security_automation.execute_response", _agent)(execute_response),
    )
    graph.add_node(
        "validate_and_learn",
        traced_node("security_automation.validate_and_learn", _agent)(validate_and_learn),
    )

    # Define edges
    graph.set_entry_point("triage_alerts")
    graph.add_conditional_edges(
        "triage_alerts",
        should_continue_after_triage,
        {
            "select_playbook": "select_playbook",
            END: END,
        },
    )
    graph.add_edge("select_playbook", "execute_response")
    graph.add_edge("execute_response", "validate_and_learn")
    graph.add_edge("validate_and_learn", END)

    return graph
