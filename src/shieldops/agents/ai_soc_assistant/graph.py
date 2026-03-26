"""LangGraph workflow for the AI SOC Assistant Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.ai_soc_assistant.models import (
    AISOCAssistantState,
)
from shieldops.agents.ai_soc_assistant.nodes import (
    gather_context,
    generate_actions,
    parse_query,
    present_results,
    reason_about_findings,
    report,
)
from shieldops.agents.tracing import traced_node


def needs_actions(
    state: AISOCAssistantState,
) -> str:
    """Route based on risk level after reasoning."""
    if state.error:
        return "report"
    reasoning = state.reasoning
    if reasoning and reasoning.risk_level in (
        "critical",
        "high",
        "medium",
    ):
        return "generate_actions"
    # Low/info risk: skip action generation
    return "present_results"


def create_ai_soc_assistant_graph() -> StateGraph[AISOCAssistantState]:
    """Build the AI SOC Assistant LangGraph workflow.

    Workflow:
        parse_query -> gather_context
            -> reason_about_findings
            -> [risk>=medium? -> generate_actions]
            -> present_results -> report -> END
    """
    graph = StateGraph(AISOCAssistantState)

    _agent = "ai_soc_assistant"
    graph.add_node(
        "parse_query",
        traced_node(
            "ai_soc_assistant.parse_query",
            _agent,
        )(parse_query),
    )
    graph.add_node(
        "gather_context",
        traced_node(
            "ai_soc_assistant.gather_context",
            _agent,
        )(gather_context),
    )
    graph.add_node(
        "reason_about_findings",
        traced_node(
            "ai_soc_assistant.reason_about_findings",
            _agent,
        )(reason_about_findings),
    )
    graph.add_node(
        "generate_actions",
        traced_node(
            "ai_soc_assistant.generate_actions",
            _agent,
        )(generate_actions),
    )
    graph.add_node(
        "present_results",
        traced_node(
            "ai_soc_assistant.present_results",
            _agent,
        )(present_results),
    )
    graph.add_node(
        "report",
        traced_node(
            "ai_soc_assistant.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("parse_query")
    graph.add_edge("parse_query", "gather_context")
    graph.add_edge(
        "gather_context",
        "reason_about_findings",
    )
    graph.add_conditional_edges(
        "reason_about_findings",
        needs_actions,
        {
            "generate_actions": "generate_actions",
            "present_results": "present_results",
            "report": "report",
        },
    )
    graph.add_edge(
        "generate_actions",
        "present_results",
    )
    graph.add_edge("present_results", "report")
    graph.add_edge("report", END)

    return graph
