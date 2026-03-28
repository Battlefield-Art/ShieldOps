"""LangGraph workflow for the Risk Prioritizer Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.risk_prioritizer.models import (
    RiskPrioritizerState,
)
from shieldops.agents.risk_prioritizer.nodes import (
    collect_findings,
    enrich_context,
    generate_action_plan,
    generate_report,
    rank_findings,
    score_risk,
)
from shieldops.agents.tracing import traced_node

_AGENT = "risk_prioritizer"


def _has_findings(
    state: RiskPrioritizerState,
) -> str:
    """Route based on whether findings exist."""
    if state.error:
        return END
    if not state.findings_collected:
        return "generate_report"
    return "enrich_context"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Risk Prioritizer StateGraph.

    Workflow:
        collect_findings
        -> [no findings? -> generate_report -> END]
        -> enrich_context -> score_risk
        -> rank_findings -> generate_action_plan
        -> generate_report -> END
    """
    graph = StateGraph(RiskPrioritizerState)

    graph.add_node(
        "collect_findings",
        traced_node(f"{_AGENT}.collect_findings", _AGENT)(collect_findings),
    )
    graph.add_node(
        "enrich_context",
        traced_node(f"{_AGENT}.enrich_context", _AGENT)(enrich_context),
    )
    graph.add_node(
        "score_risk",
        traced_node(f"{_AGENT}.score_risk", _AGENT)(score_risk),
    )
    graph.add_node(
        "rank_findings",
        traced_node(f"{_AGENT}.rank_findings", _AGENT)(rank_findings),
    )
    graph.add_node(
        "generate_action_plan",
        traced_node(f"{_AGENT}.generate_action_plan", _AGENT)(generate_action_plan),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_findings")
    graph.add_conditional_edges(
        "collect_findings",
        _has_findings,
        {
            "enrich_context": "enrich_context",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("enrich_context", "score_risk")
    graph.add_edge("score_risk", "rank_findings")
    graph.add_edge("rank_findings", "generate_action_plan")
    graph.add_edge("generate_action_plan", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_risk_prioritizer_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create the Risk Prioritizer graph."""
    return build_graph()
