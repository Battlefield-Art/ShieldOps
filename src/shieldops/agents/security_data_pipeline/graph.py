"""Security Data Pipeline Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: SecurityDataPipelineToolkit):  # type: ignore[no-untyped-def]
    """Build the security_data_pipeline agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityDataPipelineState,
        [
            ("ingest_sources", ingest_sources),
            ("transform_data", transform_data),
            ("enrich", enrich_records),
            ("validate_quality", validate_quality),
            ("load_destination", load_destination),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
