"""LangGraph workflow for the AI Model Governance Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ai_model_governance.models import (
    AIModelGovernanceState,
)
from shieldops.agents.ai_model_governance.nodes import (
    assess_risk,
    check_bias,
    enforce_policy,
    generate_report,
    inventory_models,
    validate_compliance,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ai_model_governance"


def _should_assess(
    state: AIModelGovernanceState,
) -> str:
    """Route after inventory based on results."""
    if state.error:
        return "generate_report"
    if state.model_inventory:
        return "assess_risk"
    return "generate_report"


def _should_enforce(
    state: AIModelGovernanceState,
) -> str:
    """Route after compliance check."""
    if state.non_compliant_count > 0:
        return "enforce_policy"
    return "generate_report"


def create_ai_model_governance_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the AI Model Governance LangGraph.

    Workflow:
        inventory_models
          -> [has_models?] -> assess_risk
          -> check_bias
          -> validate_compliance
          -> [non_compliant?] -> enforce_policy
          -> generate_report
    """
    graph = StateGraph(AIModelGovernanceState)

    graph.add_node(
        "inventory_models",
        traced_node(
            f"{_AGENT}.inventory_models",
            _AGENT,
        )(inventory_models),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "check_bias",
        traced_node(
            f"{_AGENT}.check_bias",
            _AGENT,
        )(check_bias),
    )
    graph.add_node(
        "validate_compliance",
        traced_node(
            f"{_AGENT}.validate_compliance",
            _AGENT,
        )(validate_compliance),
    )
    graph.add_node(
        "enforce_policy",
        traced_node(
            f"{_AGENT}.enforce_policy",
            _AGENT,
        )(enforce_policy),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("inventory_models")
    graph.add_conditional_edges(
        "inventory_models",
        _should_assess,
        {
            "assess_risk": "assess_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_risk", "check_bias")
    graph.add_edge("check_bias", "validate_compliance")
    graph.add_conditional_edges(
        "validate_compliance",
        _should_enforce,
        {
            "enforce_policy": "enforce_policy",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policy", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
