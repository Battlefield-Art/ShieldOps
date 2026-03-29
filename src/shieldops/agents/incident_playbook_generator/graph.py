"""Incident Playbook Generator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_playbook_generator.models import (
    IncidentPlaybookGeneratorState,
)
from shieldops.agents.incident_playbook_generator.nodes import (
    analyze_threat,
    design_workflow,
    generate_steps,
    map_techniques,
    report,
    validate_playbook,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_playbook_generator"


def _check_error(state: IncidentPlaybookGeneratorState) -> str:
    return "report" if state.error else "next"


def create_incident_playbook_generator_graph() -> StateGraph:
    """Build the Incident Playbook Generator workflow."""
    graph = StateGraph(IncidentPlaybookGeneratorState)

    graph.add_node(
        "analyze_threat",
        traced_node(f"{_AGENT}.analyze_threat", _AGENT)(analyze_threat),
    )
    graph.add_node(
        "map_techniques",
        traced_node(f"{_AGENT}.map_techniques", _AGENT)(map_techniques),
    )
    graph.add_node(
        "design_workflow",
        traced_node(f"{_AGENT}.design_workflow", _AGENT)(design_workflow),
    )
    graph.add_node(
        "generate_steps",
        traced_node(f"{_AGENT}.generate_steps", _AGENT)(generate_steps),
    )
    graph.add_node(
        "validate_playbook",
        traced_node(f"{_AGENT}.validate_playbook", _AGENT)(validate_playbook),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("analyze_threat")

    graph.add_conditional_edges(
        "analyze_threat",
        _check_error,
        {"next": "map_techniques", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_techniques",
        _check_error,
        {"next": "design_workflow", "report": "report"},
    )
    graph.add_conditional_edges(
        "design_workflow",
        _check_error,
        {"next": "generate_steps", "report": "report"},
    )
    graph.add_conditional_edges(
        "generate_steps",
        _check_error,
        {"next": "validate_playbook", "report": "report"},
    )
    graph.add_edge("validate_playbook", "report")
    graph.add_edge("report", END)

    return graph
