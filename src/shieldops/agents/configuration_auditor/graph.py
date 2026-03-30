"""Configuration Auditor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.configuration_auditor.models import (
    ConfigurationAuditorState,
)
from shieldops.agents.configuration_auditor.nodes import (
    collect_configs,
    detect_drift,
    parse_settings,
    recommend_fixes,
    report,
    validate_security,
)
from shieldops.agents.tracing import traced_node

_AGENT = "configuration_auditor"


def _check_error(
    state: ConfigurationAuditorState,
) -> str:
    return "report" if state.error else "next"


def create_configuration_auditor_graph() -> StateGraph:
    """Build the Configuration Auditor workflow."""
    graph = StateGraph(ConfigurationAuditorState)

    graph.add_node(
        "collect_configs",
        traced_node("ca.collect_configs", _AGENT)(collect_configs),
    )
    graph.add_node(
        "parse_settings",
        traced_node("ca.parse_settings", _AGENT)(parse_settings),
    )
    graph.add_node(
        "validate_security",
        traced_node("ca.validate_security", _AGENT)(validate_security),
    )
    graph.add_node(
        "detect_drift",
        traced_node("ca.detect_drift", _AGENT)(detect_drift),
    )
    graph.add_node(
        "recommend_fixes",
        traced_node("ca.recommend_fixes", _AGENT)(recommend_fixes),
    )
    graph.add_node(
        "report",
        traced_node("ca.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_configs")

    graph.add_conditional_edges(
        "collect_configs",
        _check_error,
        {
            "report": "report",
            "next": "parse_settings",
        },
    )
    graph.add_conditional_edges(
        "parse_settings",
        _check_error,
        {
            "report": "report",
            "next": "validate_security",
        },
    )
    graph.add_conditional_edges(
        "validate_security",
        _check_error,
        {"report": "report", "next": "detect_drift"},
    )
    graph.add_conditional_edges(
        "detect_drift",
        _check_error,
        {
            "report": "report",
            "next": "recommend_fixes",
        },
    )
    graph.add_edge("recommend_fixes", "report")
    graph.add_edge("report", END)

    return graph
