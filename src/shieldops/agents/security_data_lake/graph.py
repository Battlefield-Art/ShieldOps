"""LangGraph workflow for Security Data Lake Agent."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityDataLakeState
from .nodes import (
    analyze_data,
    execute_queries,
    identify_sources,
    merge_results,
    parse_query,
    report,
)


def build_graph(toolkit: object = None):  # type: ignore[no-untyped-def]
    """Build the security_data_lake agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityDataLakeState,
        [
            ("parse_query", parse_query),
            ("identify_sources", identify_sources),
            ("execute_queries", execute_queries),
            ("merge_results", merge_results),
            ("analyze_data", analyze_data),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_security_data_lake_graph() -> StateGraph:
    """Factory to create Security Data Lake graph."""
    return build_graph()
