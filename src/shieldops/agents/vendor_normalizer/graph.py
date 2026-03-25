"""Vendor Normalizer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import VendorNormalizerState
from .nodes import (
    detect_schema,
    emit_unified,
    enrich_context,
    ingest_telemetry,
    map_to_ocsf,
    validate_normalization,
)
from .tools import VendorNormalizerToolkit

# Maximum number of retry loops for validation failures
_MAX_RETRIES = 2


def _validation_router(state: Any) -> str:
    """Route based on validation error count.

    If the error rate exceeds 50% and we have not exhausted retries,
    loop back to detect_schema for re-mapping.  Otherwise proceed
    to enrichment.
    """
    if hasattr(state, "model_dump"):
        data = state.model_dump()
    elif isinstance(state, dict):
        data = state
    else:
        data = dict(state)

    validation_results = data.get("validation_results", [])
    stats = data.get("stats", {})
    retry_count = stats.get("validation_retries", 0)

    if not validation_results:
        return "enrich_context"

    error_count = sum(1 for r in validation_results if not r.get("valid", True))
    error_rate = error_count / max(len(validation_results), 1)

    if error_rate > 0.5 and retry_count < _MAX_RETRIES:
        # Bump retry counter in stats
        stats["validation_retries"] = retry_count + 1
        return "detect_schema"

    return "enrich_context"


def build_graph(
    toolkit: VendorNormalizerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Vendor Normalizer agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_telemetry(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_schema(_to_dict(state), toolkit)

    async def _map(state: Any) -> dict[str, Any]:
        return await map_to_ocsf(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_normalization(_to_dict(state), toolkit)

    async def _enrich(state: Any) -> dict[str, Any]:
        return await enrich_context(_to_dict(state), toolkit)

    async def _emit(state: Any) -> dict[str, Any]:
        return await emit_unified(_to_dict(state), toolkit)

    graph = StateGraph(VendorNormalizerState)
    graph.add_node("ingest_telemetry", _ingest)
    graph.add_node("detect_schema", _detect)
    graph.add_node("map_to_ocsf", _map)
    graph.add_node("validate_normalization", _validate)
    graph.add_node("enrich_context", _enrich)
    graph.add_node("emit_unified", _emit)

    graph.set_entry_point("ingest_telemetry")
    graph.add_edge("ingest_telemetry", "detect_schema")
    graph.add_edge("detect_schema", "map_to_ocsf")
    graph.add_edge("map_to_ocsf", "validate_normalization")
    graph.add_conditional_edges(
        "validate_normalization",
        _validation_router,
        {
            "detect_schema": "detect_schema",
            "enrich_context": "enrich_context",
        },
    )
    graph.add_edge("enrich_context", "emit_unified")
    graph.add_edge("emit_unified", END)

    return graph


def create_vendor_normalizer_graph(
    schema_registry: Any | None = None,
    enrichment_service: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Vendor Normalizer agent graph with dependencies."""
    toolkit = VendorNormalizerToolkit(
        schema_registry=schema_registry,
        enrichment_service=enrichment_service,
    )
    return build_graph(toolkit)
