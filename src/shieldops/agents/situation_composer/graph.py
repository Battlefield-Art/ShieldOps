"""LangGraph workflow definition for the Situation Composer Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.situation_composer.models import SituationComposerState
from shieldops.agents.situation_composer.nodes import (
    build_narrative,
    collect_alerts,
    correlate_signals,
    deduplicate,
    publish_situation,
    recommend_actions,
)
from shieldops.agents.tracing import traced_node


def has_correlations(state: SituationComposerState) -> str:
    """Route based on whether correlations were found."""
    if state.correlations:
        return "build_narrative"
    return "publish_situation"


def create_situation_composer_graph(
    alert_store: object | None = None,
    threat_intel: object | None = None,
    asset_db: object | None = None,
) -> StateGraph:
    """Build the Situation Composer Agent LangGraph workflow.

    Workflow:
        collect_alerts -> deduplicate -> correlate_signals
            -> [correlations found?]
                yes -> build_narrative -> recommend_actions -> publish_situation -> END
                no  -> publish_situation -> END
    """
    # Inject toolkit dependencies if provided
    if alert_store or threat_intel or asset_db:
        from shieldops.agents.situation_composer.nodes import set_toolkit
        from shieldops.agents.situation_composer.tools import (
            SituationComposerToolkit,
        )

        set_toolkit(
            SituationComposerToolkit(
                alert_store=alert_store,
                threat_intel=threat_intel,
                asset_db=asset_db,
            )
        )

    graph = StateGraph(SituationComposerState)

    _agent = "situation_composer"
    graph.add_node(
        "collect_alerts",
        traced_node("situation_composer.collect_alerts", _agent)(collect_alerts),
    )
    graph.add_node(
        "deduplicate",
        traced_node("situation_composer.deduplicate", _agent)(deduplicate),
    )
    graph.add_node(
        "correlate_signals",
        traced_node("situation_composer.correlate_signals", _agent)(correlate_signals),
    )
    graph.add_node(
        "build_narrative",
        traced_node("situation_composer.build_narrative", _agent)(build_narrative),
    )
    graph.add_node(
        "recommend_actions",
        traced_node("situation_composer.recommend_actions", _agent)(recommend_actions),
    )
    graph.add_node(
        "publish_situation",
        traced_node("situation_composer.publish_situation", _agent)(publish_situation),
    )

    # Define edges
    graph.set_entry_point("collect_alerts")
    graph.add_edge("collect_alerts", "deduplicate")
    graph.add_edge("deduplicate", "correlate_signals")
    graph.add_conditional_edges(
        "correlate_signals",
        has_correlations,
        {
            "build_narrative": "build_narrative",
            "publish_situation": "publish_situation",
        },
    )
    graph.add_edge("build_narrative", "recommend_actions")
    graph.add_edge("recommend_actions", "publish_situation")
    graph.add_edge("publish_situation", END)

    return graph
