"""LangGraph workflow definition for the Autonomous
Response Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.autonomous_response_engine.models import (
    AutonomousResponseEngineState,
)
from shieldops.agents.autonomous_response_engine.nodes import (
    classify_severity,
    detect_incident,
    execute_response,
    generate_report,
    select_playbook,
    validate_outcome,
)
from shieldops.agents.tracing import traced_node

_AGENT = "autonomous_response_engine"


def _should_execute(
    state: AutonomousResponseEngineState,
) -> str:
    """Route after playbook selection: execute if auto
    mode enabled and playbook selected, otherwise
    skip to report."""
    if state.error:
        return "generate_report"
    if state.selected_playbook and state.auto_execute:
        return "execute_response"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Autonomous Response Engine LangGraph
    workflow.

    Workflow:
        detect_incident -> classify_severity
            -> select_playbook
            -> [auto? -> execute_response
                -> validate_outcome]
            -> generate_report -> END
    """
    graph = StateGraph(AutonomousResponseEngineState)

    graph.add_node(
        "detect_incident",
        traced_node(f"{_AGENT}.detect_incident", _AGENT)(detect_incident),
    )
    graph.add_node(
        "classify_severity",
        traced_node(f"{_AGENT}.classify_severity", _AGENT)(classify_severity),
    )
    graph.add_node(
        "select_playbook",
        traced_node(f"{_AGENT}.select_playbook", _AGENT)(select_playbook),
    )
    graph.add_node(
        "execute_response",
        traced_node(f"{_AGENT}.execute_response", _AGENT)(execute_response),
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
    graph.set_entry_point("detect_incident")
    graph.add_edge("detect_incident", "classify_severity")
    graph.add_edge("classify_severity", "select_playbook")
    graph.add_conditional_edges(
        "select_playbook",
        _should_execute,
        {
            "execute_response": "execute_response",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("execute_response", "validate_outcome")
    graph.add_edge("validate_outcome", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_autonomous_response_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Autonomous Response Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
