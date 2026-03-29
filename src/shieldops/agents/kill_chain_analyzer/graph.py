"""Kill Chain Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.kill_chain_analyzer.models import KillChainAnalyzerState
from shieldops.agents.kill_chain_analyzer.nodes import (
    correlate_stages,
    identify_gaps,
    ingest_alerts,
    map_kill_chain,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "kill_chain_analyzer"


def _check_error(state: KillChainAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_kill_chain_analyzer_graph() -> StateGraph:
    """Build the Kill Chain Analyzer workflow."""
    graph = StateGraph(KillChainAnalyzerState)

    graph.add_node(
        "ingest_alerts",
        traced_node(f"{_AGENT}.ingest_alerts", _AGENT)(ingest_alerts),
    )
    graph.add_node(
        "map_kill_chain",
        traced_node(f"{_AGENT}.map_kill_chain", _AGENT)(map_kill_chain),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "correlate_stages",
        traced_node(f"{_AGENT}.correlate_stages", _AGENT)(correlate_stages),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("ingest_alerts")

    graph.add_conditional_edges(
        "ingest_alerts",
        _check_error,
        {"next": "map_kill_chain", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_kill_chain",
        _check_error,
        {"next": "identify_gaps", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_gaps",
        _check_error,
        {"next": "correlate_stages", "report": "report"},
    )
    graph.add_conditional_edges(
        "correlate_stages",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
