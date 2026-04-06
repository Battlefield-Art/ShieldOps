"""LangGraph workflow definition for the Incident Playbook Engine."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import IncidentPlaybookEngineState
from .nodes import (
    adapt_steps,
    classify_incident,
    execute_playbook,
    generate_report,
    select_playbook,
    validate_outcome,
)


def build_graph():  # type: ignore[no-untyped-def]
    """Build the incident_playbook_engine agent graph (linear sequence)."""
    return build_linear_graph(
        IncidentPlaybookEngineState,
        [
            ("classify_incident", classify_incident),
            ("select_playbook", select_playbook),
            ("adapt_steps", adapt_steps),
            ("execute_playbook", execute_playbook),
            ("validate_outcome", validate_outcome),
            ("generate_report", generate_report),
        ],
    )


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
