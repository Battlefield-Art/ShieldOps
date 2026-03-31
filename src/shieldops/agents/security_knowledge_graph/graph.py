"""Security Knowledge Graph Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityKnowledgeGraphState
from .nodes import (
    analyze_paths,
    build_relationships,
    detect_patterns,
    generate_report,
    ingest_entities,
    query_insights,
)
from .tools import SecurityKnowledgeGraphToolkit


def build_graph(
    toolkit: SecurityKnowledgeGraphToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Knowledge Graph graph.

    Flow:
        ingest_entities -> build_relationships
        -> analyze_paths -> detect_patterns
        -> query_insights -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(
        state: Any,
    ) -> dict[str, Any]:
        return await ingest_entities(
            _to_dict(state),
            toolkit,
        )

    async def _build(
        state: Any,
    ) -> dict[str, Any]:
        return await build_relationships(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_paths(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_patterns(
            _to_dict(state),
            toolkit,
        )

    async def _query(
        state: Any,
    ) -> dict[str, Any]:
        return await query_insights(
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

    graph = StateGraph(SecurityKnowledgeGraphState)
    graph.add_node("ingest_entities", _ingest)
    graph.add_node("build_relationships", _build)
    graph.add_node("analyze_paths", _analyze)
    graph.add_node("detect_patterns", _detect)
    graph.add_node("query_insights", _query)
    graph.add_node("report", _report)

    graph.set_entry_point("ingest_entities")
    graph.add_edge(
        "ingest_entities",
        "build_relationships",
    )
    graph.add_edge(
        "build_relationships",
        "analyze_paths",
    )
    graph.add_edge(
        "analyze_paths",
        "detect_patterns",
    )
    graph.add_edge(
        "detect_patterns",
        "query_insights",
    )
    graph.add_edge(
        "query_insights",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_knowledge_graph_graph(
    graph_store: Any | None = None,
    threat_intel_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Knowledge Graph graph."""
    toolkit = SecurityKnowledgeGraphToolkit(
        graph_store=graph_store,
        threat_intel_api=threat_intel_api,
    )
    return build_graph(toolkit)
