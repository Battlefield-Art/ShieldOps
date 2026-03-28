"""LangGraph workflow for the Finding Correlator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.finding_correlator.models import (
    FindingCorrelatorState,
)
from shieldops.agents.finding_correlator.nodes import (
    collect_findings,
    correlate_related,
    deduplicate,
    generate_report,
    normalize_findings,
    prioritize,
)
from shieldops.agents.tracing import traced_node

_AGENT = "finding_correlator"


def _has_findings(
    state: FindingCorrelatorState,
) -> str:
    """Route based on whether findings exist."""
    if state.error:
        return END
    if not state.raw_findings:
        return "generate_report"
    return "normalize_findings"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Finding Correlator StateGraph.

    Workflow:
        collect_findings
        -> [no findings? -> generate_report -> END]
        -> normalize_findings -> deduplicate
        -> correlate_related -> prioritize
        -> generate_report -> END
    """
    graph = StateGraph(FindingCorrelatorState)

    graph.add_node(
        "collect_findings",
        traced_node(f"{_AGENT}.collect_findings", _AGENT)(collect_findings),
    )
    graph.add_node(
        "normalize_findings",
        traced_node(f"{_AGENT}.normalize_findings", _AGENT)(normalize_findings),
    )
    graph.add_node(
        "deduplicate",
        traced_node(f"{_AGENT}.deduplicate", _AGENT)(deduplicate),
    )
    graph.add_node(
        "correlate_related",
        traced_node(f"{_AGENT}.correlate_related", _AGENT)(correlate_related),
    )
    graph.add_node(
        "prioritize",
        traced_node(f"{_AGENT}.prioritize", _AGENT)(prioritize),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_findings")
    graph.add_conditional_edges(
        "collect_findings",
        _has_findings,
        {
            "normalize_findings": ("normalize_findings"),
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("normalize_findings", "deduplicate")
    graph.add_edge("deduplicate", "correlate_related")
    graph.add_edge("correlate_related", "prioritize")
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_finding_correlator_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create the Finding Correlator graph."""
    return build_graph()
