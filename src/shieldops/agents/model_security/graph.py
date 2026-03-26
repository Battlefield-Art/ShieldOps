"""Model Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ModelSecurityState
from .nodes import (
    assess_integrity,
    detect_backdoors,
    evaluate_risks,
    scan_models,
    verify_provenance,
)
from .tools import ModelSecurityToolkit


def build_graph(toolkit: ModelSecurityToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Model Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_models(_to_dict(state), toolkit)

    async def _provenance(state: Any) -> dict[str, Any]:
        return await verify_provenance(_to_dict(state), toolkit)

    async def _backdoors(state: Any) -> dict[str, Any]:
        return await detect_backdoors(_to_dict(state), toolkit)

    async def _integrity(state: Any) -> dict[str, Any]:
        return await assess_integrity(_to_dict(state), toolkit)

    async def _risks(state: Any) -> dict[str, Any]:
        return await evaluate_risks(_to_dict(state), toolkit)

    graph = StateGraph(ModelSecurityState)
    graph.add_node("scan_models", _scan)
    graph.add_node("verify_provenance", _provenance)
    graph.add_node("detect_backdoors", _backdoors)
    graph.add_node("assess_integrity", _integrity)
    graph.add_node("evaluate_risks", _risks)

    graph.set_entry_point("scan_models")
    graph.add_edge("scan_models", "verify_provenance")
    graph.add_edge("verify_provenance", "detect_backdoors")
    graph.add_edge("detect_backdoors", "assess_integrity")
    graph.add_edge("assess_integrity", "evaluate_risks")
    graph.add_edge("evaluate_risks", END)

    return graph


def create_model_security_graph(
    model_registry_client: Any | None = None,
    provenance_service: Any | None = None,
    scanning_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Model Security agent graph with dependencies."""
    toolkit = ModelSecurityToolkit(
        model_registry_client=model_registry_client,
        provenance_service=provenance_service,
        scanning_engine=scanning_engine,
    )
    return build_graph(toolkit)
