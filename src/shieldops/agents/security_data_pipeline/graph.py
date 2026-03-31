"""Security Data Pipeline Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityDataPipelineState
from .nodes import (
    enrich_records,
    generate_report,
    ingest_sources,
    load_destination,
    transform_data,
    validate_quality,
)
from .tools import SecurityDataPipelineToolkit


def build_graph(
    toolkit: SecurityDataPipelineToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Data Pipeline graph.

    Flow:
        ingest_sources -> transform_data
        -> enrich -> validate_quality
        -> load_destination -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(
        state: Any,
    ) -> dict[str, Any]:
        return await ingest_sources(
            _to_dict(state),
            toolkit,
        )

    async def _transform(
        state: Any,
    ) -> dict[str, Any]:
        return await transform_data(
            _to_dict(state),
            toolkit,
        )

    async def _enrich(
        state: Any,
    ) -> dict[str, Any]:
        return await enrich_records(
            _to_dict(state),
            toolkit,
        )

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_quality(
            _to_dict(state),
            toolkit,
        )

    async def _load(
        state: Any,
    ) -> dict[str, Any]:
        return await load_destination(
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

    graph = StateGraph(SecurityDataPipelineState)
    graph.add_node("ingest_sources", _ingest)
    graph.add_node("transform_data", _transform)
    graph.add_node("enrich", _enrich)
    graph.add_node("validate_quality", _validate)
    graph.add_node("load_destination", _load)
    graph.add_node("report", _report)

    graph.set_entry_point("ingest_sources")
    graph.add_edge(
        "ingest_sources",
        "transform_data",
    )
    graph.add_edge(
        "transform_data",
        "enrich",
    )
    graph.add_edge(
        "enrich",
        "validate_quality",
    )
    graph.add_edge(
        "validate_quality",
        "load_destination",
    )
    graph.add_edge(
        "load_destination",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_data_pipeline_graph(
    data_sources: Any | None = None,
    enrichment_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Data Pipeline graph."""
    toolkit = SecurityDataPipelineToolkit(
        data_sources=data_sources,
        enrichment_api=enrichment_api,
    )
    return build_graph(toolkit)
