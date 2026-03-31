"""LangGraph workflow definition for the SIEM Rule
Optimizer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.siem_rule_optimizer.models import (
    SIEMRuleOptimizerState,
)
from shieldops.agents.siem_rule_optimizer.nodes import (
    analyze_performance,
    collect_rules,
    detect_overlap,
    generate_report,
    tune_thresholds,
    validate_rules,
)
from shieldops.agents.tracing import traced_node

_AGENT = "siem_rule_optimizer"


def _should_tune(
    state: SIEMRuleOptimizerState,
) -> str:
    """Route after overlap detection: tune thresholds
    if overlaps or performance issues found, otherwise
    skip to report."""
    if state.error:
        return "generate_report"
    if state.overlap_count > 0 or len(state.performance_data) > 0:
        return "tune_thresholds"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the SIEM Rule Optimizer LangGraph workflow.

    Workflow:
        collect_rules -> analyze_performance
            -> detect_overlap
            -> [issues? -> tune_thresholds -> validate]
            -> generate_report -> END
    """
    graph = StateGraph(SIEMRuleOptimizerState)

    graph.add_node(
        "collect_rules",
        traced_node(f"{_AGENT}.collect_rules", _AGENT)(collect_rules),
    )
    graph.add_node(
        "analyze_performance",
        traced_node(f"{_AGENT}.analyze_performance", _AGENT)(analyze_performance),
    )
    graph.add_node(
        "detect_overlap",
        traced_node(f"{_AGENT}.detect_overlap", _AGENT)(detect_overlap),
    )
    graph.add_node(
        "tune_thresholds",
        traced_node(f"{_AGENT}.tune_thresholds", _AGENT)(tune_thresholds),
    )
    graph.add_node(
        "validate_rules",
        traced_node(f"{_AGENT}.validate_rules", _AGENT)(validate_rules),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_rules")
    graph.add_edge("collect_rules", "analyze_performance")
    graph.add_edge("analyze_performance", "detect_overlap")
    graph.add_conditional_edges(
        "detect_overlap",
        _should_tune,
        {
            "tune_thresholds": "tune_thresholds",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("tune_thresholds", "validate_rules")
    graph.add_edge("validate_rules", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_siem_rule_optimizer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a SIEM Rule Optimizer graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
