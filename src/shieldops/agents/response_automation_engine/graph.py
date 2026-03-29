"""LangGraph workflow for the Response Automation Engine."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.response_automation_engine.models import (
    ResponseAutomationEngineState,
)
from shieldops.agents.response_automation_engine.nodes import (
    detect_trigger,
    document_actions,
    evaluate_playbook,
    orchestrate_actions,
    report,
    verify_response,
)
from shieldops.agents.tracing import traced_node

_AGENT = "response_automation_engine"


def _check_error(
    state: ResponseAutomationEngineState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_response_automation_engine_graph() -> StateGraph[ResponseAutomationEngineState]:
    """Build the Response Automation Engine workflow."""
    graph = StateGraph(ResponseAutomationEngineState)

    graph.add_node(
        "detect_trigger",
        traced_node(
            "rae.detect_trigger",
            _AGENT,
        )(detect_trigger),
    )
    graph.add_node(
        "evaluate_playbook",
        traced_node(
            "rae.evaluate_playbook",
            _AGENT,
        )(evaluate_playbook),
    )
    graph.add_node(
        "orchestrate_actions",
        traced_node(
            "rae.orchestrate_actions",
            _AGENT,
        )(orchestrate_actions),
    )
    graph.add_node(
        "verify_response",
        traced_node(
            "rae.verify_response",
            _AGENT,
        )(verify_response),
    )
    graph.add_node(
        "document_actions",
        traced_node(
            "rae.document_actions",
            _AGENT,
        )(document_actions),
    )
    graph.add_node(
        "report",
        traced_node(
            "rae.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("detect_trigger")

    graph.add_conditional_edges(
        "detect_trigger",
        _check_error,
        {
            "report": "report",
            "next": "evaluate_playbook",
        },
    )
    graph.add_conditional_edges(
        "evaluate_playbook",
        _check_error,
        {
            "report": "report",
            "next": "orchestrate_actions",
        },
    )
    graph.add_conditional_edges(
        "orchestrate_actions",
        _check_error,
        {
            "report": "report",
            "next": "verify_response",
        },
    )
    graph.add_conditional_edges(
        "verify_response",
        _check_error,
        {
            "report": "report",
            "next": "document_actions",
        },
    )
    graph.add_edge("document_actions", "report")
    graph.add_edge("report", END)

    return graph
