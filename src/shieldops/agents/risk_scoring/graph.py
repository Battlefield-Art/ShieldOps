"""Risk Scoring Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import RiskScoringState
from .nodes import (
    aggregate_by_entity,
    collect_observations,
    decide_actions,
    enrich_observations,
)
from .tools import RiskScoringToolkit


def build_graph(toolkit: RiskScoringToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Risk Scoring agent graph."""

    async def _collect(state: dict[str, Any]) -> dict[str, Any]:
        return await collect_observations(state, toolkit)

    async def _enrich(state: dict[str, Any]) -> dict[str, Any]:
        return await enrich_observations(state, toolkit)

    async def _aggregate(state: dict[str, Any]) -> dict[str, Any]:
        return await aggregate_by_entity(state, toolkit)

    async def _decide(state: dict[str, Any]) -> dict[str, Any]:
        return await decide_actions(state, toolkit)

    graph = StateGraph(RiskScoringState)
    graph.add_node("collect", _collect)  # type: ignore[type-var]
    graph.add_node("enrich", _enrich)  # type: ignore[type-var]
    graph.add_node("aggregate", _aggregate)  # type: ignore[type-var]
    graph.add_node("decide", _decide)  # type: ignore[type-var]

    graph.set_entry_point("collect")
    graph.add_edge("collect", "enrich")
    graph.add_edge("enrich", "aggregate")
    graph.add_edge("aggregate", "decide")
    graph.add_edge("decide", END)

    return graph
