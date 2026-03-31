"""Security Workflow Builder Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: SecurityWorkflowBuilderToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Workflow Builder graph.

    Flow:
        define_trigger -> build_workflow
        -> validate_logic -> test_execution
        -> deploy_workflow -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _trigger(
        state: Any,
    ) -> dict[str, Any]:
        return await define_trigger(
            _to_dict(state),
            toolkit,
        )

    async def _build(
        state: Any,
    ) -> dict[str, Any]:
        return await build_workflow(
            _to_dict(state),
            toolkit,
        )

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_logic(
            _to_dict(state),
            toolkit,
        )

    async def _test(
        state: Any,
    ) -> dict[str, Any]:
        return await test_execution(
            _to_dict(state),
            toolkit,
        )

    async def _deploy(
        state: Any,
    ) -> dict[str, Any]:
        return await deploy_workflow(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(SecurityWorkflowBuilderState)
    graph.add_node("define_trigger", _trigger)
    graph.add_node("build_workflow", _build)
    graph.add_node("validate_logic", _validate)
    graph.add_node("test_execution", _test)
    graph.add_node("deploy_workflow", _deploy)
    graph.add_node("report", _report)

    graph.set_entry_point("define_trigger")
    graph.add_edge(
        "define_trigger",
        "build_workflow",
    )
    graph.add_edge(
        "build_workflow",
        "validate_logic",
    )
    graph.add_edge(
        "validate_logic",
        "test_execution",
    )
    graph.add_edge(
        "test_execution",
        "deploy_workflow",
    )
    graph.add_edge(
        "deploy_workflow",
        "report",
    )
    graph.add_edge("report", END)

    return graph


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
