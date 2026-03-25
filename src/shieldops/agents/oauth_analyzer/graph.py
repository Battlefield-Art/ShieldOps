"""LangGraph workflow definition for the OAuth Grant Analyzer Agent."""

from __future__ import annotations

from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.oauth_analyzer.models import OAuthAnalyzerState
from shieldops.agents.oauth_analyzer.nodes import (
    assess_risk,
    classify_permissions,
    detect_anomalies,
    discover_grants,
    generate_report,
    recommend_actions,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def has_anomalies(state: OAuthAnalyzerState) -> str:
    """Route based on whether anomalies were found."""
    if state.error:
        return "generate_report"
    if state.anomalies:
        return "recommend_actions"
    # Also route to recommendations if high-risk grants exist
    high_risk = any(g.risk_score >= 70 for g in state.discovered_grants)
    if high_risk:
        return "recommend_actions"
    return "generate_report"


def create_oauth_analyzer_graph(
    identity_provider: Any | None = None,
    saas_registry: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:
    """Build the OAuth Grant Analyzer Agent LangGraph workflow.

    Workflow:
        discover_grants -> classify_permissions -> assess_risk -> detect_anomalies
            -> [conditional: recommend_actions OR generate_report]
            -> generate_report -> END

    Args:
        identity_provider: Optional live identity provider connector.
        saas_registry: Optional SaaS application registry.
        threat_intel: Optional threat intelligence feed.

    Returns:
        A compiled-ready StateGraph.
    """
    # Toolkit is configured via runner.set_toolkit(); factory params are
    # reserved for future direct-wiring of connectors into the graph.
    graph = StateGraph(OAuthAnalyzerState)

    _agent = "oauth_analyzer"
    graph.add_node(
        "discover_grants",
        traced_node("oauth_analyzer.discover_grants", _agent)(discover_grants),
    )
    graph.add_node(
        "classify_permissions",
        traced_node("oauth_analyzer.classify_permissions", _agent)(classify_permissions),
    )
    graph.add_node(
        "assess_risk",
        traced_node("oauth_analyzer.assess_risk", _agent)(assess_risk),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node("oauth_analyzer.detect_anomalies", _agent)(detect_anomalies),
    )
    graph.add_node(
        "recommend_actions",
        traced_node("oauth_analyzer.recommend_actions", _agent)(recommend_actions),
    )
    graph.add_node(
        "generate_report",
        traced_node("oauth_analyzer.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("discover_grants")
    graph.add_edge("discover_grants", "classify_permissions")
    graph.add_edge("classify_permissions", "assess_risk")
    graph.add_edge("assess_risk", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        has_anomalies,
        {
            "recommend_actions": "recommend_actions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_actions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
