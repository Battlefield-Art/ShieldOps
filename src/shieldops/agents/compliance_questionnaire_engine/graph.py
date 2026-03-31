"""LangGraph workflow definition for the Compliance
Questionnaire Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.compliance_questionnaire_engine.models import (
    ComplianceQuestionnaireEngineState,
)
from shieldops.agents.compliance_questionnaire_engine.nodes import (
    finalize_response,
    generate_answers,
    generate_report,
    map_controls,
    receive_questionnaire,
    review_gaps,
)
from shieldops.agents.tracing import traced_node

_AGENT = "compliance_questionnaire_engine"


def _should_finalize(
    state: ComplianceQuestionnaireEngineState,
) -> str:
    """Route after gap review: finalize if answers exist
    or skip to report on error."""
    if state.error:
        return "generate_report"
    if state.answered_count > 0:
        return "finalize_response"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Questionnaire Engine LangGraph
    workflow.

    Workflow:
        receive_questionnaire -> map_controls
            -> generate_answers -> review_gaps
            -> [answers? -> finalize_response]
            -> generate_report -> END
    """
    graph = StateGraph(ComplianceQuestionnaireEngineState)

    graph.add_node(
        "receive_questionnaire",
        traced_node(
            f"{_AGENT}.receive_questionnaire",
            _AGENT,
        )(receive_questionnaire),
    )
    graph.add_node(
        "map_controls",
        traced_node(f"{_AGENT}.map_controls", _AGENT)(map_controls),
    )
    graph.add_node(
        "generate_answers",
        traced_node(f"{_AGENT}.generate_answers", _AGENT)(generate_answers),
    )
    graph.add_node(
        "review_gaps",
        traced_node(f"{_AGENT}.review_gaps", _AGENT)(review_gaps),
    )
    graph.add_node(
        "finalize_response",
        traced_node(
            f"{_AGENT}.finalize_response",
            _AGENT,
        )(finalize_response),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("receive_questionnaire")
    graph.add_edge("receive_questionnaire", "map_controls")
    graph.add_edge("map_controls", "generate_answers")
    graph.add_edge("generate_answers", "review_gaps")
    graph.add_conditional_edges(
        "review_gaps",
        _should_finalize,
        {
            "finalize_response": "finalize_response",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("finalize_response", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_compliance_questionnaire_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Compliance Questionnaire Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
