"""LangGraph workflow for Custom Agent Factory."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.custom_agent_factory.models import (
    CustomAgentFactoryState,
)
from shieldops.agents.custom_agent_factory.nodes import (
    design_agent,
    generate_code,
    parse_requirements,
    register_agent,
    report,
    validate_agent,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Custom Agent Factory workflow.

    Workflow::

        parse_requirements -> design_agent
            -> generate_code -> validate_agent
            -> register_agent -> report -> END
    """
    _a = "custom_agent_factory"
    graph = StateGraph(CustomAgentFactoryState)

    graph.add_node(
        "parse_requirements",
        traced_node(f"{_a}.parse_requirements", _a)(parse_requirements),
    )
    graph.add_node(
        "design_agent",
        traced_node(f"{_a}.design_agent", _a)(design_agent),
    )
    graph.add_node(
        "generate_code",
        traced_node(f"{_a}.generate_code", _a)(generate_code),
    )
    graph.add_node(
        "validate_agent",
        traced_node(f"{_a}.validate_agent", _a)(validate_agent),
    )
    graph.add_node(
        "register_agent",
        traced_node(f"{_a}.register_agent", _a)(register_agent),
    )
    graph.add_node(
        "report",
        traced_node(f"{_a}.report", _a)(report),
    )

    graph.set_entry_point("parse_requirements")
    graph.add_edge("parse_requirements", "design_agent")
    graph.add_edge("design_agent", "generate_code")
    graph.add_edge("generate_code", "validate_agent")
    graph.add_edge("validate_agent", "register_agent")
    graph.add_edge("register_agent", "report")
    graph.add_edge("report", END)

    return graph


def create_custom_agent_factory_graph() -> StateGraph:
    """Factory to create Custom Agent Factory graph."""
    return build_graph()
