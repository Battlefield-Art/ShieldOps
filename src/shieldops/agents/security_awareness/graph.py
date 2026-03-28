"""LangGraph workflow definition for the Security Awareness Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_awareness.models import (
    SecurityAwarenessState,
)
from shieldops.agents.security_awareness.nodes import (
    assess_baseline,
    recommend,
    report,
    run_simulations,
    score_risk,
    track_training,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_awareness"


def _route_after_baseline(
    state: SecurityAwarenessState,
) -> str:
    """Route after baseline: proceed or jump to report."""
    if state.error:
        return "report"
    return "run_simulations"


def create_security_awareness_graph() -> StateGraph[SecurityAwarenessState]:
    """Build the Security Awareness Agent LangGraph workflow.

    Workflow:
        assess_baseline -> [conditional: run_simulations OR report]
        run_simulations -> track_training -> score_risk
            -> recommend -> report -> END
    """
    graph = StateGraph(SecurityAwarenessState)

    graph.add_node(
        "assess_baseline",
        traced_node(
            "awareness.assess_baseline",
            _AGENT,
        )(assess_baseline),
    )
    graph.add_node(
        "run_simulations",
        traced_node(
            "awareness.run_simulations",
            _AGENT,
        )(run_simulations),
    )
    graph.add_node(
        "track_training",
        traced_node(
            "awareness.track_training",
            _AGENT,
        )(track_training),
    )
    graph.add_node(
        "score_risk",
        traced_node(
            "awareness.score_risk",
            _AGENT,
        )(score_risk),
    )
    graph.add_node(
        "recommend",
        traced_node(
            "awareness.recommend",
            _AGENT,
        )(recommend),
    )
    graph.add_node(
        "report",
        traced_node(
            "awareness.report",
            _AGENT,
        )(report),
    )

    # Define edges
    graph.set_entry_point("assess_baseline")
    graph.add_conditional_edges(
        "assess_baseline",
        _route_after_baseline,
        {
            "run_simulations": "run_simulations",
            "report": "report",
        },
    )
    graph.add_edge("run_simulations", "track_training")
    graph.add_edge("track_training", "score_risk")
    graph.add_edge("score_risk", "recommend")
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
