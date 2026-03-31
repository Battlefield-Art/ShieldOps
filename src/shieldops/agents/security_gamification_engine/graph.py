"""LangGraph workflow definition for the Security
Gamification Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_gamification_engine.models import (
    SecurityGamificationEngineState,
)
from shieldops.agents.security_gamification_engine.nodes import (
    award_badges,
    define_challenges,
    generate_report,
    score_performance,
    track_participation,
    update_leaderboard,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_gamification_engine"


def _should_award(
    state: SecurityGamificationEngineState,
) -> str:
    """Route after leaderboard: award badges if entries
    exist or skip to report on error."""
    if state.error:
        return "generate_report"
    if state.leaderboard:
        return "award_badges"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Gamification Engine LangGraph
    workflow.

    Workflow:
        define_challenges -> track_participation
            -> score_performance -> update_leaderboard
            -> [entries? -> award_badges]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityGamificationEngineState)

    graph.add_node(
        "define_challenges",
        traced_node(f"{_AGENT}.define_challenges", _AGENT)(define_challenges),
    )
    graph.add_node(
        "track_participation",
        traced_node(f"{_AGENT}.track_participation", _AGENT)(track_participation),
    )
    graph.add_node(
        "score_performance",
        traced_node(f"{_AGENT}.score_performance", _AGENT)(score_performance),
    )
    graph.add_node(
        "update_leaderboard",
        traced_node(f"{_AGENT}.update_leaderboard", _AGENT)(update_leaderboard),
    )
    graph.add_node(
        "award_badges",
        traced_node(f"{_AGENT}.award_badges", _AGENT)(award_badges),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("define_challenges")
    graph.add_edge("define_challenges", "track_participation")
    graph.add_edge("track_participation", "score_performance")
    graph.add_edge("score_performance", "update_leaderboard")
    graph.add_conditional_edges(
        "update_leaderboard",
        _should_award,
        {
            "award_badges": "award_badges",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("award_badges", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_gamification_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Gamification Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
