"""LangGraph workflow definition for the IR Playbook Engine Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ir_playbook_engine.models import (
    IRPlaybookEngineState,
)
from shieldops.agents.ir_playbook_engine.nodes import (
    adapt_response,
    classify_incident,
    execute_steps,
    report,
    select_playbook,
    validate_containment,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ir_playbook_engine"


def _route_after_classify(
    state: IRPlaybookEngineState,
) -> str:
    if state.error:
        return "report"
    return "select_playbook"


def _route_after_select(
    state: IRPlaybookEngineState,
) -> str:
    if state.error:
        return "report"
    return "execute_steps"


def _route_after_execute(
    state: IRPlaybookEngineState,
) -> str:
    if state.error:
        return "report"
    return "adapt_response"


def _route_after_adapt(
    state: IRPlaybookEngineState,
) -> str:
    if state.error:
        return "report"
    return "validate_containment"


def _route_after_validate(
    state: IRPlaybookEngineState,
) -> str:
    return "report"


def create_ir_playbook_engine_graph() -> StateGraph:
    """Build the IR Playbook Engine LangGraph workflow.

    Workflow:
        classify_incident -> select_playbook -> execute_steps
        -> adapt_response -> validate_containment -> report -> END

    Error at any stage short-circuits to report.
    """
    graph = StateGraph(IRPlaybookEngineState)

    graph.add_node(
        "classify_incident",
        traced_node(f"{_AGENT}.classify_incident", _AGENT)(classify_incident),
    )
    graph.add_node(
        "select_playbook",
        traced_node(f"{_AGENT}.select_playbook", _AGENT)(select_playbook),
    )
    graph.add_node(
        "execute_steps",
        traced_node(f"{_AGENT}.execute_steps", _AGENT)(execute_steps),
    )
    graph.add_node(
        "adapt_response",
        traced_node(f"{_AGENT}.adapt_response", _AGENT)(adapt_response),
    )
    graph.add_node(
        "validate_containment",
        traced_node(f"{_AGENT}.validate_containment", _AGENT)(validate_containment),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("classify_incident")

    graph.add_conditional_edges(
        "classify_incident",
        _route_after_classify,
        {
            "select_playbook": "select_playbook",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "select_playbook",
        _route_after_select,
        {
            "execute_steps": "execute_steps",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "execute_steps",
        _route_after_execute,
        {
            "adapt_response": "adapt_response",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "adapt_response",
        _route_after_adapt,
        {
            "validate_containment": "validate_containment",
            "report": "report",
        },
    )
    graph.add_edge("validate_containment", "report")
    graph.add_edge("report", END)

    return graph
