"""Data Intelligence Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DataIntelligenceState
from .nodes import (
    assess_data_risk,
    classify_with_ai,
    discover_data,
    map_data_lineage,
    recommend_protection,
    report,
)
from .tools import DataIntelligenceToolkit


def build_graph(toolkit: DataIntelligenceToolkit):  # type: ignore[no-untyped-def]
    """Build the data_intelligence agent graph (linear sequence)."""
    return build_linear_graph(
        DataIntelligenceState,
        [
            ("discover_data", discover_data),
            ("classify_with_ai", classify_with_ai),
            ("map_data_lineage", map_data_lineage),
            ("assess_data_risk", assess_data_risk),
            ("recommend_protection", recommend_protection),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_data_intelligence_graph(
    catalog_client: Any | None = None,
    classifier: Any | None = None,
    lineage_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Intelligence graph."""
    toolkit = DataIntelligenceToolkit(
        catalog_client=catalog_client,
        classifier=classifier,
        lineage_api=lineage_api,
    )
    return build_graph(toolkit)
