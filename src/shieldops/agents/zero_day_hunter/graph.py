"""LangGraph workflow definition for the Zero Day
Hunter Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.zero_day_hunter.models import (
    ZeroDayHunterState,
)
from shieldops.agents.zero_day_hunter.nodes import (
    analyze_exploits,
    assess_exposure,
    deploy_mitigations,
    develop_signatures,
    generate_report,
    monitor_feeds,
)

_AGENT = "zero_day_hunter"


def _should_mitigate(
    state: ZeroDayHunterState,
) -> str:
    """Route after signature development: deploy
    mitigations if critical exposures exist, otherwise
    skip to report."""
    if state.error:
        return "generate_report"
    if state.critical_exposures > 0:
        return "deploy_mitigations"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Zero Day Hunter LangGraph workflow.

    Workflow:
        monitor_feeds -> analyze_exploits
            -> assess_exposure -> develop_signatures
            -> [critical? -> deploy_mitigations]
            -> generate_report -> END
    """
    graph = StateGraph(ZeroDayHunterState)

    graph.add_node(
        "monitor_feeds",
        traced_node(f"{_AGENT}.monitor_feeds", _AGENT)(monitor_feeds),
    )
    graph.add_node(
        "analyze_exploits",
        traced_node(f"{_AGENT}.analyze_exploits", _AGENT)(analyze_exploits),
    )
    graph.add_node(
        "assess_exposure",
        traced_node(f"{_AGENT}.assess_exposure", _AGENT)(assess_exposure),
    )
    graph.add_node(
        "develop_signatures",
        traced_node(f"{_AGENT}.develop_signatures", _AGENT)(develop_signatures),
    )
    graph.add_node(
        "deploy_mitigations",
        traced_node(f"{_AGENT}.deploy_mitigations", _AGENT)(deploy_mitigations),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("monitor_feeds")
    graph.add_edge("monitor_feeds", "analyze_exploits")
    graph.add_edge("analyze_exploits", "assess_exposure")
    graph.add_edge("assess_exposure", "develop_signatures")
    graph.add_conditional_edges(
        "develop_signatures",
        _should_mitigate,
        {
            "deploy_mitigations": "deploy_mitigations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("deploy_mitigations", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_zero_day_hunter_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Zero Day Hunter graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
