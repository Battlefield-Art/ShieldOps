"""LangGraph workflow for the Security Automation Hub."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.security_automation_hub.models import (
    SecurityAutomationHubState,
)
from shieldops.agents.security_automation_hub.nodes import (
    execute_automations,
    generate_report,
    ingest_triggers,
    learn_outcomes,
    match_playbooks,
    validate_results,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "security_automation_hub"


def _check_error(
    state: SecurityAutomationHubState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "generate_report"
    return "next"


def create_security_automation_hub_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Security Automation Hub LangGraph workflow.

    Workflow:
        ingest_triggers
        -> match_playbooks
        -> execute_automations
        -> validate_results
        -> learn_outcomes
        -> generate_report
        -> END
    """
    graph = StateGraph(SecurityAutomationHubState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "ingest_triggers",
        traced_node(
            f"{_AGENT}.ingest_triggers",
            _AGENT,
        )(ingest_triggers),
    )
    graph.add_node(
        "match_playbooks",
        traced_node(
            f"{_AGENT}.match_playbooks",
            _AGENT,
        )(match_playbooks),
    )
    graph.add_node(
        "execute_automations",
        traced_node(
            f"{_AGENT}.execute_automations",
            _AGENT,
        )(execute_automations),
    )
    graph.add_node(
        "validate_results",
        traced_node(
            f"{_AGENT}.validate_results",
            _AGENT,
        )(validate_results),
    )
    graph.add_node(
        "learn_outcomes",
        traced_node(
            f"{_AGENT}.learn_outcomes",
            _AGENT,
        )(learn_outcomes),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("ingest_triggers")
    graph.add_conditional_edges(
        "ingest_triggers",
        _check_error,
        {"next": "match_playbooks", "generate_report": "generate_report"},
    )
    graph.add_conditional_edges(
        "match_playbooks",
        _check_error,
        {
            "next": "execute_automations",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "execute_automations",
        _check_error,
        {
            "next": "validate_results",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "validate_results",
        _check_error,
        {
            "next": "learn_outcomes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("learn_outcomes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
