"""LangGraph StateGraph definition for the Evolution Engine Agent."""

from __future__ import annotations

import functools

from langgraph.graph import END, StateGraph

from shieldops.agents.evolution.models import EvolutionState
from shieldops.agents.evolution.nodes import (
    analyze_patterns,
    deploy_changes,
    evolve_prompts,
    generate_report,
    measure_fitness,
    propagate_learnings,
    validate_evolution,
)
from shieldops.agents.evolution.tools import EvolutionToolkit


def _has_candidates(state: dict) -> str:
    """Route based on whether candidates were found."""
    candidates = state.get("candidates", [])
    if not candidates:
        return "report"
    return "analyze_patterns"


def _has_mutations(state: dict) -> str:
    """Route based on whether mutations were generated."""
    mutations = state.get("mutations", [])
    if not mutations:
        return "propagate_learnings"
    return "deploy_changes"


def build_graph(toolkit: EvolutionToolkit) -> StateGraph:
    """Build the evolution engine LangGraph StateGraph.

    Workflow:
        measure_fitness
          → [has candidates?]
            → analyze_patterns → evolve_prompts
              → [has mutations?]
                → deploy_changes → validate_evolution → report
              → propagate_learnings → report
          → report (no candidates)
    """
    graph = StateGraph(EvolutionState)

    # Bind toolkit to nodes
    _measure = functools.partial(measure_fitness, toolkit=toolkit)
    _analyze = functools.partial(analyze_patterns, toolkit=toolkit)
    _evolve = functools.partial(evolve_prompts, toolkit=toolkit)
    _propagate = functools.partial(propagate_learnings, toolkit=toolkit)
    _deploy = functools.partial(deploy_changes, toolkit=toolkit)
    _validate = functools.partial(validate_evolution, toolkit=toolkit)
    _report = functools.partial(generate_report, toolkit=toolkit)

    # Add nodes
    graph.add_node("measure_fitness", _measure)
    graph.add_node("analyze_patterns", _analyze)
    graph.add_node("evolve_prompts", _evolve)
    graph.add_node("propagate_learnings", _propagate)
    graph.add_node("deploy_changes", _deploy)
    graph.add_node("validate_evolution", _validate)
    graph.add_node("report", _report)

    # Set entry point
    graph.set_entry_point("measure_fitness")

    # Edges
    graph.add_conditional_edges(
        "measure_fitness",
        _has_candidates,
        {
            "analyze_patterns": "analyze_patterns",
            "report": "report",
        },
    )
    graph.add_edge("analyze_patterns", "evolve_prompts")
    graph.add_edge("evolve_prompts", "propagate_learnings")
    graph.add_conditional_edges(
        "propagate_learnings",
        _has_mutations,
        {
            "deploy_changes": "deploy_changes",
            "propagate_learnings": "report",
        },
    )
    graph.add_edge("deploy_changes", "validate_evolution")
    graph.add_edge("validate_evolution", "report")
    graph.add_edge("report", END)

    return graph


def create_evolution_graph() -> StateGraph:
    """Factory function to create a fully wired evolution engine graph."""
    toolkit = EvolutionToolkit()
    return build_graph(toolkit)
