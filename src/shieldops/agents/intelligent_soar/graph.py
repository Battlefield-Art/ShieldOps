"""LangGraph workflow for the Intelligent SOAR Agent.

Composable, AI-reasoning playbooks that adapt
mid-execution — directly counters Palo Alto's
Cortex XSOAR legacy drag-and-drop approach.
"""

from langgraph.graph import END, StateGraph

from shieldops.agents.intelligent_soar.models import (
    IntelligentSOARState,
)
from shieldops.agents.intelligent_soar.nodes import (
    adapt_dynamically,
    execute_steps,
    receive_trigger,
    report,
    select_playbook,
    validate_outcome,
)
from shieldops.agents.tracing import traced_node


def should_continue(
    state: IntelligentSOARState,
) -> str:
    """Route after trigger: select or report error."""
    if state.error:
        return "report"
    return "select_playbook"


def should_adapt(
    state: IntelligentSOARState,
) -> str:
    """Route after execution: adapt or validate."""
    if state.error:
        return "report"
    # In dry_run mode, skip adaptation
    if state.execution_mode == "dry_run":
        return "validate_outcome"
    return "adapt_dynamically"


def create_intelligent_soar_graph() -> StateGraph[IntelligentSOARState]:
    """Build the Intelligent SOAR LangGraph workflow.

    Stages:
      receive_trigger -> select_playbook ->
      execute_steps -> adapt_dynamically ->
      validate_outcome -> report
    """
    graph = StateGraph(IntelligentSOARState)

    _agent = "intelligent_soar"
    graph.add_node(
        "receive_trigger",
        traced_node(
            "intelligent_soar.receive_trigger",
            _agent,
        )(receive_trigger),
    )
    graph.add_node(
        "select_playbook",
        traced_node(
            "intelligent_soar.select_playbook",
            _agent,
        )(select_playbook),
    )
    graph.add_node(
        "execute_steps",
        traced_node(
            "intelligent_soar.execute_steps",
            _agent,
        )(execute_steps),
    )
    graph.add_node(
        "adapt_dynamically",
        traced_node(
            "intelligent_soar.adapt_dynamically",
            _agent,
        )(adapt_dynamically),
    )
    graph.add_node(
        "validate_outcome",
        traced_node(
            "intelligent_soar.validate_outcome",
            _agent,
        )(validate_outcome),
    )
    graph.add_node(
        "report",
        traced_node(
            "intelligent_soar.report",
            _agent,
        )(report),
    )

    graph.set_entry_point("receive_trigger")

    graph.add_conditional_edges(
        "receive_trigger",
        should_continue,
        {
            "select_playbook": "select_playbook",
            "report": "report",
        },
    )
    graph.add_edge(
        "select_playbook",
        "execute_steps",
    )
    graph.add_conditional_edges(
        "execute_steps",
        should_adapt,
        {
            "adapt_dynamically": "adapt_dynamically",
            "validate_outcome": "validate_outcome",
            "report": "report",
        },
    )
    graph.add_edge(
        "adapt_dynamically",
        "validate_outcome",
    )
    graph.add_edge(
        "validate_outcome",
        "report",
    )
    graph.add_edge("report", END)

    return graph
