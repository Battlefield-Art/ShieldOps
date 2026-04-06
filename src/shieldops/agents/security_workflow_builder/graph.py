"""Security Workflow Builder Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityWorkflowBuilderState
from .nodes import (
    build_workflow,
    define_trigger,
    deploy_workflow,
    generate_report,
    test_execution,
    validate_logic,
)
from .tools import SecurityWorkflowBuilderToolkit


def build_graph(toolkit: SecurityWorkflowBuilderToolkit):  # type: ignore[no-untyped-def]
    """Build the security_workflow_builder agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityWorkflowBuilderState,
        [
            ("define_trigger", define_trigger),
            ("build_workflow", build_workflow),
            ("validate_logic", validate_logic),
            ("test_execution", test_execution),
            ("deploy_workflow", deploy_workflow),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_workflow_builder_graph(
    workflow_store: Any | None = None,
    execution_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Workflow Builder graph."""
    toolkit = SecurityWorkflowBuilderToolkit(
        workflow_store=workflow_store,
        execution_engine=execution_engine,
    )
    return build_graph(toolkit)
