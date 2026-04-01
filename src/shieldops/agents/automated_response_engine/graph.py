"""LangGraph workflow for the Automated Response Engine Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.automated_response_engine.models import (
    AutomatedResponseEngineState,
)
from shieldops.agents.automated_response_engine.nodes import (
    assess_incident,
    execute_actions,
    generate_report,
    plan_remediation,
    select_playbook,
    validate_response,
)
from shieldops.agents.tracing import traced_node

_AGENT = "automated_response_engine"


def _should_plan(
    state: AutomatedResponseEngineState,
) -> str:
    """Route after playbook selection."""
    if state.error:
        return "generate_report"
    if state.selected_playbooks:
        return "plan_remediation"
    return "generate_report"


def _should_validate(
    state: AutomatedResponseEngineState,
) -> str:
    """Route after action execution."""
    if state.execution_results:
        return "validate_response"
    return "generate_report"


def create_automated_response_engine_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Automated Response Engine LangGraph.

    Workflow:
        assess_incident -> select_playbook
          -> [has_playbooks?] -> plan_remediation -> execute_actions
          -> [has_results?] -> validate_response -> generate_report
    """
    graph = StateGraph(AutomatedResponseEngineState)

    graph.add_node(
        "assess_incident",
        traced_node(f"{_AGENT}.assess_incident", _AGENT)(assess_incident),
    )
    graph.add_node(
        "select_playbook",
        traced_node(f"{_AGENT}.select_playbook", _AGENT)(select_playbook),
    )
    graph.add_node(
        "plan_remediation",
        traced_node(f"{_AGENT}.plan_remediation", _AGENT)(plan_remediation),
    )
    graph.add_node(
        "execute_actions",
        traced_node(f"{_AGENT}.execute_actions", _AGENT)(execute_actions),
    )
    graph.add_node(
        "validate_response",
        traced_node(f"{_AGENT}.validate_response", _AGENT)(validate_response),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("assess_incident")
    graph.add_edge("assess_incident", "select_playbook")
    graph.add_conditional_edges(
        "select_playbook",
        _should_plan,
        {
            "plan_remediation": "plan_remediation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("plan_remediation", "execute_actions")
    graph.add_conditional_edges(
        "execute_actions",
        _should_validate,
        {
            "validate_response": "validate_response",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_response", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
