"""LangGraph workflow for the Unified Threat Model Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.unified_threat_model.models import (
    UnifiedThreatModelState,
)
from shieldops.agents.unified_threat_model.nodes import (
    analyze_controls,
    calculate_risk,
    define_scope,
    generate_report,
    identify_threats,
    prioritize_mitigations,
)

_AGENT = "unified_threat_model"


def _should_identify(
    state: UnifiedThreatModelState,
) -> str:
    """Route after scope definition."""
    if state.error:
        return "generate_report"
    if state.threat_scope:
        return "identify_threats"
    return "generate_report"


def _should_prioritize(
    state: UnifiedThreatModelState,
) -> str:
    """Route after risk calculation."""
    if state.max_risk_score > 30.0:
        return "prioritize_mitigations"
    return "generate_report"


def create_unified_threat_model_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Unified Threat Model LangGraph.

    Workflow:
        define_scope
          -> [has_scope?] -> identify_threats
          -> analyze_controls
          -> calculate_risk
          -> [high_risk?] -> prioritize_mitigations
          -> generate_report
    """
    graph = StateGraph(UnifiedThreatModelState)

    graph.add_node(
        "define_scope",
        traced_node(
            f"{_AGENT}.define_scope",
            _AGENT,
        )(define_scope),
    )
    graph.add_node(
        "identify_threats",
        traced_node(
            f"{_AGENT}.identify_threats",
            _AGENT,
        )(identify_threats),
    )
    graph.add_node(
        "analyze_controls",
        traced_node(
            f"{_AGENT}.analyze_controls",
            _AGENT,
        )(analyze_controls),
    )
    graph.add_node(
        "calculate_risk",
        traced_node(
            f"{_AGENT}.calculate_risk",
            _AGENT,
        )(calculate_risk),
    )
    graph.add_node(
        "prioritize_mitigations",
        traced_node(
            f"{_AGENT}.prioritize_mitigations",
            _AGENT,
        )(prioritize_mitigations),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("define_scope")
    graph.add_conditional_edges(
        "define_scope",
        _should_identify,
        {
            "identify_threats": "identify_threats",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("identify_threats", "analyze_controls")
    graph.add_edge("analyze_controls", "calculate_risk")
    graph.add_conditional_edges(
        "calculate_risk",
        _should_prioritize,
        {
            "prioritize_mitigations": "prioritize_mitigations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("prioritize_mitigations", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
