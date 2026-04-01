"""LangGraph workflow for the Security Knowledge Graph Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_knowledge_graph.models import (
    SecurityKnowledgeGraphState,
)
from shieldops.agents.security_knowledge_graph.nodes import (
    build_graph,
    detect_anomalies,
    extract_relationships,
    generate_report,
    ingest_entities,
    query_patterns,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_knowledge_graph"


def _should_query(
    state: SecurityKnowledgeGraphState,
) -> str:
    """Route after graph building."""
    if state.error:
        return "generate_report"
    if state.patterns:
        return "query_patterns"
    return "generate_report"


def _should_detect(
    state: SecurityKnowledgeGraphState,
) -> str:
    """Route after pattern querying."""
    if state.patterns:
        return "detect_anomalies"
    return "generate_report"


def create_security_knowledge_graph_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Knowledge Graph LangGraph.

    Workflow:
        ingest_entities -> extract_relationships -> build_graph
          -> [has_patterns?] -> query_patterns
          -> [has_patterns?] -> detect_anomalies -> generate_report
    """
    graph = StateGraph(SecurityKnowledgeGraphState)

    graph.add_node(
        "ingest_entities",
        traced_node(f"{_AGENT}.ingest_entities", _AGENT)(ingest_entities),
    )
    graph.add_node(
        "extract_relationships",
        traced_node(f"{_AGENT}.extract_relationships", _AGENT)(extract_relationships),
    )
    graph.add_node(
        "build_graph",
        traced_node(f"{_AGENT}.build_graph", _AGENT)(build_graph),
    )
    graph.add_node(
        "query_patterns",
        traced_node(f"{_AGENT}.query_patterns", _AGENT)(query_patterns),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("ingest_entities")
    graph.add_edge("ingest_entities", "extract_relationships")
    graph.add_edge("extract_relationships", "build_graph")
    graph.add_conditional_edges(
        "build_graph",
        _should_query,
        {
            "query_patterns": "query_patterns",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "query_patterns",
        _should_detect,
        {
            "detect_anomalies": "detect_anomalies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_anomalies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
