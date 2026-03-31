"""LangGraph workflow definition for the Security
Copilot Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_copilot_agent.models import (
    SecurityCopilotAgentState,
)
from shieldops.agents.security_copilot_agent.nodes import (
    analyze,
    execute_action,
    gather_context,
    generate_report,
    receive_query,
    recommend,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_copilot_agent"


def _should_execute(
    state: SecurityCopilotAgentState,
) -> str:
    """Route after recommend: execute if automated actions
    exist or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    has_automated = any(r.get("automated", False) for r in state.recommendations)
    if has_automated:
        return "execute_action"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Copilot Agent LangGraph
    workflow.

    Workflow:
        receive_query -> gather_context -> analyze
            -> recommend -> [automated? -> execute_action]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityCopilotAgentState)

    graph.add_node(
        "receive_query",
        traced_node(f"{_AGENT}.receive_query", _AGENT)(receive_query),
    )
    graph.add_node(
        "gather_context",
        traced_node(f"{_AGENT}.gather_context", _AGENT)(gather_context),
    )
    graph.add_node(
        "analyze",
        traced_node(f"{_AGENT}.analyze", _AGENT)(analyze),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "execute_action",
        traced_node(f"{_AGENT}.execute_action", _AGENT)(execute_action),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("receive_query")
    graph.add_edge("receive_query", "gather_context")
    graph.add_edge("gather_context", "analyze")
    graph.add_edge("analyze", "recommend")
    graph.add_conditional_edges(
        "recommend",
        _should_execute,
        {
            "execute_action": "execute_action",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("execute_action", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_copilot_agent_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Copilot Agent
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
