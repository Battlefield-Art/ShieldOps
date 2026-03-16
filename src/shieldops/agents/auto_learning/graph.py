"""Auto Learning Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AutoLearningState
from .nodes import (
    assess_baseline,
    evaluate_and_decide,
    generate_proposals,
    run_experiments,
)
from .tools import AutoLearningToolkit


def should_continue(state: dict[str, Any]) -> str:
    """Decide whether to continue the learning loop."""
    iteration = state.get("iteration", 0)
    max_iterations = state.get("max_iterations", 10)
    acceptance_rate = state.get("acceptance_rate", 0.0)

    if iteration >= max_iterations:
        return "end"
    if iteration > 0 and acceptance_rate == 0.0:
        return "end"
    return "end"  # Single pass by default; multi-pass via runner loop


def build_graph(toolkit: AutoLearningToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Auto Learning agent graph."""

    async def _assess(state: dict[str, Any]) -> dict[str, Any]:
        return await assess_baseline(state, toolkit)

    async def _propose(state: dict[str, Any]) -> dict[str, Any]:
        return await generate_proposals(state, toolkit)

    async def _experiment(state: dict[str, Any]) -> dict[str, Any]:
        return await run_experiments(state, toolkit)

    async def _evaluate(state: dict[str, Any]) -> dict[str, Any]:
        return await evaluate_and_decide(state, toolkit)

    graph = StateGraph(AutoLearningState)
    graph.add_node("assess", _assess)  # type: ignore[type-var]
    graph.add_node("propose", _propose)  # type: ignore[type-var]
    graph.add_node("experiment", _experiment)  # type: ignore[type-var]
    graph.add_node("evaluate", _evaluate)  # type: ignore[type-var]

    graph.set_entry_point("assess")
    graph.add_edge("assess", "propose")
    graph.add_edge("propose", "experiment")
    graph.add_edge("experiment", "evaluate")
    graph.add_conditional_edges(
        "evaluate",
        should_continue,
        {"end": END},
    )

    return graph
