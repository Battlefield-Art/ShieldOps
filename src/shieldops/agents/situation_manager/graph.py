"""LangGraph workflow for the Situation Manager Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.situation_manager.models import (
    SituationManagerState,
)
from shieldops.agents.situation_manager.nodes import (
    aggregate_alerts,
    compose_narrative,
    generate_report,
    prioritize_situations,
    recommend_actions,
    track_outcomes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "situation_manager"


def _has_aggregates(
    state: SituationManagerState,
) -> str:
    """Route based on whether aggregates exist."""
    if state.error:
        return END
    if not state.aggregates:
        return "generate_report"
    return "compose_narrative"


def _has_situations(
    state: SituationManagerState,
) -> str:
    """Route based on whether situations exist."""
    if state.error:
        return END
    if not state.situations:
        return "generate_report"
    return "recommend_actions"


def create_situation_manager_graph() -> StateGraph:
    """Build the Situation Manager workflow.

    Workflow:
        aggregate_alerts
            -> [no aggregates? -> report -> END]
            -> compose_narrative
            -> prioritize_situations
            -> [no situations? -> report -> END]
            -> recommend_actions
            -> track_outcomes
            -> generate_report -> END
    """
    graph = StateGraph(SituationManagerState)

    graph.add_node(
        "aggregate_alerts",
        traced_node(
            "situation_manager.aggregate_alerts",
            _AGENT,
        )(aggregate_alerts),
    )
    graph.add_node(
        "compose_narrative",
        traced_node(
            "situation_manager.compose_narrative",
            _AGENT,
        )(compose_narrative),
    )
    graph.add_node(
        "prioritize_situations",
        traced_node(
            "situation_manager.prioritize_situations",
            _AGENT,
        )(prioritize_situations),
    )
    graph.add_node(
        "recommend_actions",
        traced_node(
            "situation_manager.recommend_actions",
            _AGENT,
        )(recommend_actions),
    )
    graph.add_node(
        "track_outcomes",
        traced_node(
            "situation_manager.track_outcomes",
            _AGENT,
        )(track_outcomes),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "situation_manager.generate_report",
            _AGENT,
        )(generate_report),
    )

    graph.set_entry_point("aggregate_alerts")
    graph.add_conditional_edges(
        "aggregate_alerts",
        _has_aggregates,
        {
            "compose_narrative": "compose_narrative",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge(
        "compose_narrative",
        "prioritize_situations",
    )
    graph.add_conditional_edges(
        "prioritize_situations",
        _has_situations,
        {
            "recommend_actions": "recommend_actions",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("recommend_actions", "track_outcomes")
    graph.add_edge("track_outcomes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
