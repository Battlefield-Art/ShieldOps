"""LangGraph workflow for Custom Agent Factory."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CustomAgentFactoryState
from .nodes import (
    design_agent,
    generate_code,
    parse_requirements,
    register_agent,
    report,
    validate_agent,
)


def build_graph(toolkit: object = None):  # type: ignore[no-untyped-def]
    """Build the custom_agent_factory agent graph (linear sequence)."""
    return build_linear_graph(
        CustomAgentFactoryState,
        [
            ("parse_requirements", parse_requirements),
            ("design_agent", design_agent),
            ("generate_code", generate_code),
            ("validate_agent", validate_agent),
            ("register_agent", register_agent),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_custom_agent_factory_graph() -> StateGraph:
    """Factory to create Custom Agent Factory graph."""
    return build_graph()
