"""LangGraph workflow for the IOC Enrichment Engine."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ioc_enrichment_engine.models import (
    IOCEnrichmentEngineState,
)
from shieldops.agents.ioc_enrichment_engine.nodes import (
    assess_risk,
    collect_iocs,
    correlate_context,
    query_sources,
    report,
    tag_indicators,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ioc_enrichment_engine"


def _check_error(
    state: IOCEnrichmentEngineState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_ioc_enrichment_engine_graph() -> StateGraph[IOCEnrichmentEngineState]:
    """Build the IOC Enrichment Engine workflow."""
    graph = StateGraph(IOCEnrichmentEngineState)

    graph.add_node(
        "collect_iocs",
        traced_node(
            "iee.collect_iocs",
            _AGENT,
        )(collect_iocs),
    )
    graph.add_node(
        "query_sources",
        traced_node(
            "iee.query_sources",
            _AGENT,
        )(query_sources),
    )
    graph.add_node(
        "correlate_context",
        traced_node(
            "iee.correlate_context",
            _AGENT,
        )(correlate_context),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            "iee.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "tag_indicators",
        traced_node(
            "iee.tag_indicators",
            _AGENT,
        )(tag_indicators),
    )
    graph.add_node(
        "report",
        traced_node(
            "iee.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("collect_iocs")

    graph.add_conditional_edges(
        "collect_iocs",
        _check_error,
        {"report": "report", "next": "query_sources"},
    )
    graph.add_conditional_edges(
        "query_sources",
        _check_error,
        {"report": "report", "next": "correlate_context"},
    )
    graph.add_conditional_edges(
        "correlate_context",
        _check_error,
        {"report": "report", "next": "assess_risk"},
    )
    graph.add_conditional_edges(
        "assess_risk",
        _check_error,
        {"report": "report", "next": "tag_indicators"},
    )
    graph.add_edge("tag_indicators", "report")
    graph.add_edge("report", END)

    return graph
