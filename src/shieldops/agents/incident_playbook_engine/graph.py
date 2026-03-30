"""LangGraph workflow definition for the Incident Playbook Engine."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_playbook_engine.models import (
    IncidentPlaybookEngineState,
)
from shieldops.agents.incident_playbook_engine.nodes import (
    adapt_steps,
    classify_incident,
    execute_playbook,
    generate_report,
    select_playbook,
    validate_outcome,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_playbook_engine"


def build_graph() -> StateGraph:
    """Build the Incident Playbook Engine LangGraph workflow.

    Workflow:
        classify_incident -> select_playbook -> adapt_steps
        -> execute_playbook -> validate_outcome
        -> generate_report -> END
    """
    graph = StateGraph(IncidentPlaybookEngineState)

    graph.add_node(
        "classify_incident",
        traced_node("ipe.classify_incident", _AGENT)(classify_incident),
    )
    graph.add_node(
        "select_playbook",
        traced_node("ipe.select_playbook", _AGENT)(select_playbook),
    )
    graph.add_node(
        "adapt_steps",
        traced_node("ipe.adapt_steps", _AGENT)(adapt_steps),
    )
    graph.add_node(
        "execute_playbook",
        traced_node("ipe.execute_playbook", _AGENT)(execute_playbook),
    )
    graph.add_node(
        "validate_outcome",
        traced_node("ipe.validate_outcome", _AGENT)(validate_outcome),
    )
    graph.add_node(
        "generate_report",
        traced_node("ipe.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("classify_incident")
    graph.add_edge("classify_incident", "select_playbook")
    graph.add_edge("select_playbook", "adapt_steps")
    graph.add_edge("adapt_steps", "execute_playbook")
    graph.add_edge("execute_playbook", "validate_outcome")
    graph.add_edge("validate_outcome", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_incident_playbook_engine_graph(
    playbook_db: object | None = None,
    outcome_db: object | None = None,
) -> StateGraph:
    """Factory: create and return the workflow graph.

    Args:
        playbook_db: Optional playbook database client.
        outcome_db: Optional outcome history database client.

    Returns:
        Configured StateGraph ready for compilation.
    """
    from shieldops.agents.incident_playbook_engine.nodes import (
        set_toolkit,
    )
    from shieldops.agents.incident_playbook_engine.tools import (
        IncidentPlaybookEngineToolkit,
    )

    toolkit = IncidentPlaybookEngineToolkit(
        playbook_db=playbook_db,
        outcome_db=outcome_db,
    )
    set_toolkit(toolkit)
    return build_graph()
