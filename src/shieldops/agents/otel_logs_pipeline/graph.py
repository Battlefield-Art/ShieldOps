"""OTel Logs Pipeline Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelLogsPipelineState
from .nodes import (
    configure_pipeline,
    discover_sources,
    test_parsing,
    validate_correlation,
)
from .tools import OTelLogsPipelineToolkit


def build_graph(toolkit: OTelLogsPipelineToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the OTel Logs Pipeline agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_sources(_to_dict(state), toolkit)

    async def _configure(state: Any) -> dict[str, Any]:
        return await configure_pipeline(_to_dict(state), toolkit)

    async def _parse(state: Any) -> dict[str, Any]:
        return await test_parsing(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_correlation(_to_dict(state), toolkit)

    graph = StateGraph(OTelLogsPipelineState)
    graph.add_node("discover", _discover)
    graph.add_node("configure", _configure)
    graph.add_node("test_parsing", _parse)
    graph.add_node("validate", _validate)

    graph.set_entry_point("discover")
    graph.add_edge("discover", "configure")
    graph.add_edge("configure", "test_parsing")
    graph.add_edge("test_parsing", "validate")
    graph.add_edge("validate", END)

    return graph


def create_otel_logs_pipeline_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Logs Pipeline graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelLogsPipelineToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
