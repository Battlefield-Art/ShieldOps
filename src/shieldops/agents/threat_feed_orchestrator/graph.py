"""LangGraph workflow definition for the Threat Feed
Orchestrator Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_feed_orchestrator.models import (
    ThreatFeedOrchestratorState,
)
from shieldops.agents.threat_feed_orchestrator.nodes import (
    connect_feeds,
    deduplicate,
    distribute,
    enrich,
    generate_report,
    normalize,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_feed_orchestrator"


def _should_distribute(
    state: ThreatFeedOrchestratorState,
) -> str:
    """Route after enrichment: distribute if consumers
    configured and indicators exist, otherwise report."""
    if state.error:
        return "generate_report"
    if state.enriched_count > 0 and state.consumer_configs:
        return "distribute"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Feed Orchestrator LangGraph
    workflow.

    Workflow:
        connect_feeds -> normalize -> deduplicate
            -> enrich -> [consumers? -> distribute]
            -> generate_report -> END
    """
    graph = StateGraph(ThreatFeedOrchestratorState)

    graph.add_node(
        "connect_feeds",
        traced_node(f"{_AGENT}.connect_feeds", _AGENT)(connect_feeds),
    )
    graph.add_node(
        "normalize",
        traced_node(f"{_AGENT}.normalize", _AGENT)(normalize),
    )
    graph.add_node(
        "deduplicate",
        traced_node(f"{_AGENT}.deduplicate", _AGENT)(deduplicate),
    )
    graph.add_node(
        "enrich",
        traced_node(f"{_AGENT}.enrich", _AGENT)(enrich),
    )
    graph.add_node(
        "distribute",
        traced_node(f"{_AGENT}.distribute", _AGENT)(distribute),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("connect_feeds")
    graph.add_edge("connect_feeds", "normalize")
    graph.add_edge("normalize", "deduplicate")
    graph.add_edge("deduplicate", "enrich")
    graph.add_conditional_edges(
        "enrich",
        _should_distribute,
        {
            "distribute": "distribute",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("distribute", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_threat_feed_orchestrator_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Threat Feed Orchestrator
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
