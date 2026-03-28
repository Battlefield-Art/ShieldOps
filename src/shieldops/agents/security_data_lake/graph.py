"""LangGraph workflow for Security Data Lake Agent."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.security_data_lake.models import (
    SecurityDataLakeState,
)
from shieldops.agents.security_data_lake.nodes import (
    analyze_data,
    execute_queries,
    identify_sources,
    merge_results,
    parse_query,
    report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Security Data Lake workflow.

    Workflow::

        parse_query -> identify_sources
            -> execute_queries -> merge_results
            -> analyze_data -> report -> END
    """
    _a = "security_data_lake"
    graph = StateGraph(SecurityDataLakeState)

    graph.add_node(
        "parse_query",
        traced_node(f"{_a}.parse_query", _a)(parse_query),
    )
    graph.add_node(
        "identify_sources",
        traced_node(f"{_a}.identify_sources", _a)(identify_sources),
    )
    graph.add_node(
        "execute_queries",
        traced_node(f"{_a}.execute_queries", _a)(execute_queries),
    )
    graph.add_node(
        "merge_results",
        traced_node(f"{_a}.merge_results", _a)(merge_results),
    )
    graph.add_node(
        "analyze_data",
        traced_node(f"{_a}.analyze_data", _a)(analyze_data),
    )
    graph.add_node(
        "report",
        traced_node(f"{_a}.report", _a)(report),
    )

    graph.set_entry_point("parse_query")
    graph.add_edge("parse_query", "identify_sources")
    graph.add_edge("identify_sources", "execute_queries")
    graph.add_edge("execute_queries", "merge_results")
    graph.add_edge("merge_results", "analyze_data")
    graph.add_edge("analyze_data", "report")
    graph.add_edge("report", END)

    return graph


def create_security_data_lake_graph() -> StateGraph:
    """Factory to create Security Data Lake graph."""
    return build_graph()
