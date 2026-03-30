"""LangGraph workflow definition for the Security
Orchestration Hub Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_orchestration_hub.models import (
    SecurityOrchestrationHubState,
)
from shieldops.agents.security_orchestration_hub.nodes import (
    classify_severity,
    execute_actions,
    generate_report,
    ingest_event,
    route_playbook,
    validate_outcome,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_orchestration_hub"


def _should_validate(
    state: SecurityOrchestrationHubState,
) -> str:
    """Route after execution: validate if actions exist
    or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.actions_executed > 0:
        return "validate_outcome"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Orchestration Hub LangGraph
    workflow.

    Workflow:
        ingest_event -> classify_severity
            -> route_playbook -> execute_actions
            -> [actions? -> validate_outcome]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityOrchestrationHubState)

    graph.add_node(
        "ingest_event",
        traced_node(f"{_AGENT}.ingest_event", _AGENT)(ingest_event),
    )
    graph.add_node(
        "classify_severity",
        traced_node(f"{_AGENT}.classify_severity", _AGENT)(classify_severity),
    )
    graph.add_node(
        "route_playbook",
        traced_node(f"{_AGENT}.route_playbook", _AGENT)(route_playbook),
    )
    graph.add_node(
        "execute_actions",
        traced_node(f"{_AGENT}.execute_actions", _AGENT)(execute_actions),
    )
    graph.add_node(
        "validate_outcome",
        traced_node(f"{_AGENT}.validate_outcome", _AGENT)(validate_outcome),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("ingest_event")
    graph.add_edge("ingest_event", "classify_severity")
    graph.add_edge("classify_severity", "route_playbook")
    graph.add_edge("route_playbook", "execute_actions")
    graph.add_conditional_edges(
        "execute_actions",
        _should_validate,
        {
            "validate_outcome": "validate_outcome",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_outcome", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_orchestration_hub_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Orchestration Hub
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
