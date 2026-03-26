"""LangGraph workflow definition for the Config Validator Agent."""

from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.config_validator.models import ConfigValidatorState
from shieldops.agents.config_validator.nodes import (
    assess_impact,
    collect_configs,
    compare_baselines,
    detect_drift,
    generate_report,
    remediate,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_remediate(state: ConfigValidatorState) -> str:
    """Route based on whether drifts were detected.

    If drifts exist, proceed to remediation. Otherwise skip to report.
    """
    if state.drifts:
        return "remediate"
    return "generate_report"


def should_report_after_remediation(state: ConfigValidatorState) -> str:  # noqa: ARG001
    """Always proceed to report after remediation."""
    return "generate_report"


def create_config_validator_graph() -> StateGraph[ConfigValidatorState]:
    """Build the Config Validator Agent LangGraph workflow.

    Workflow:
        collect_configs → compare_baselines → detect_drift → assess_impact
            → [conditional: drifts exist → remediate → generate_report]
            → [conditional: no drifts → generate_report]
            → END
    """
    _agent = "config_validator"
    graph: StateGraph[Any] = StateGraph(ConfigValidatorState)

    # Add nodes (wrapped with OTEL tracing spans)
    graph.add_node(
        "collect_configs",
        traced_node("config_validator.collect_configs", _agent)(collect_configs),
    )
    graph.add_node(
        "compare_baselines",
        traced_node("config_validator.compare_baselines", _agent)(compare_baselines),
    )
    graph.add_node(
        "detect_drift",
        traced_node("config_validator.detect_drift", _agent)(detect_drift),
    )
    graph.add_node(
        "assess_impact",
        traced_node("config_validator.assess_impact", _agent)(assess_impact),
    )
    graph.add_node(
        "remediate",
        traced_node("config_validator.remediate", _agent)(remediate),
    )
    graph.add_node(
        "generate_report",
        traced_node("config_validator.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_configs")
    graph.add_edge("collect_configs", "compare_baselines")
    graph.add_edge("compare_baselines", "detect_drift")
    graph.add_edge("detect_drift", "assess_impact")
    graph.add_conditional_edges(
        "assess_impact",
        should_remediate,
        {
            "remediate": "remediate",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
