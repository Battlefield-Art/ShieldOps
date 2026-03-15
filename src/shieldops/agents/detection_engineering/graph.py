"""Detection Engineering Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DetectionEngineeringState
from .nodes import (
    assess_coverage,
    backtest_and_tune,
    create_rules,
    deploy_rules,
)
from .tools import DetectionEngineeringToolkit


def _should_deploy(state: Any) -> str:
    """Route based on whether any rules have FP rate below 5%."""
    if hasattr(state, "tuning_results"):
        _tuning_results = state.tuning_results
    else:
        _tuning_results = state.get("tuning_results", [])

    if hasattr(state, "rules_created"):
        rules = state.rules_created
    else:
        rules = state.get("rules_created", [])

    # Check if any rules have acceptable FP rates
    for rule_data in rules:
        fp_rate = (
            rule_data.get("false_positive_rate", 1.0)
            if isinstance(rule_data, dict)
            else rule_data.false_positive_rate
        )
        if fp_rate < 0.05:
            return "deploy"

    return "end"


def build_graph(toolkit: DetectionEngineeringToolkit) -> StateGraph:
    """Build the Detection Engineering agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_coverage(_to_dict(state), toolkit)

    async def _create(state: Any) -> dict[str, Any]:
        return await create_rules(_to_dict(state), toolkit)

    async def _test_tune(state: Any) -> dict[str, Any]:
        return await backtest_and_tune(_to_dict(state), toolkit)

    async def _deploy(state: Any) -> dict[str, Any]:
        return await deploy_rules(_to_dict(state), toolkit)

    graph = StateGraph(DetectionEngineeringState)
    graph.add_node("assess_coverage", _assess)
    graph.add_node("create_rules", _create)
    graph.add_node("test_and_tune", _test_tune)
    graph.add_node("deploy_rules", _deploy)

    graph.set_entry_point("assess_coverage")
    graph.add_edge("assess_coverage", "create_rules")
    graph.add_edge("create_rules", "test_and_tune")
    graph.add_conditional_edges(
        "test_and_tune",
        _should_deploy,
        {"deploy": "deploy_rules", "end": END},
    )
    graph.add_edge("deploy_rules", END)

    return graph


def create_detection_engineering_graph(
    siem_client: Any | None = None,
    mitre_client: Any | None = None,
    rule_store: Any | None = None,
) -> StateGraph:
    """Create the Detection Engineering agent graph with dependencies."""
    toolkit = DetectionEngineeringToolkit(
        siem_client=siem_client,
        mitre_client=mitre_client,
        rule_store=rule_store,
    )
    return build_graph(toolkit)
