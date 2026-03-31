"""LangGraph workflow definition for the Cloud
Governance Enforcer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_governance_enforcer.models import (
    CloudGovernanceEnforcerState,
)
from shieldops.agents.cloud_governance_enforcer.nodes import (
    check_tags,
    detect_violations,
    evaluate_policies,
    generate_report,
    remediate,
    scan_resources,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_governance_enforcer"


def _should_remediate(
    state: CloudGovernanceEnforcerState,
) -> str:
    """Route after violation detection: remediate if
    violations exist and auto-remediate is enabled,
    otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_violations > 0 and state.auto_remediate:
        return "remediate"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Governance Enforcer LangGraph
    workflow.

    Workflow:
        scan_resources -> check_tags -> evaluate_policies
            -> detect_violations
            -> [violations + auto? -> remediate]
            -> generate_report -> END
    """
    graph = StateGraph(CloudGovernanceEnforcerState)

    graph.add_node(
        "scan_resources",
        traced_node(f"{_AGENT}.scan_resources", _AGENT)(scan_resources),
    )
    graph.add_node(
        "check_tags",
        traced_node(f"{_AGENT}.check_tags", _AGENT)(check_tags),
    )
    graph.add_node(
        "evaluate_policies",
        traced_node(f"{_AGENT}.evaluate_policies", _AGENT)(evaluate_policies),
    )
    graph.add_node(
        "detect_violations",
        traced_node(f"{_AGENT}.detect_violations", _AGENT)(detect_violations),
    )
    graph.add_node(
        "remediate",
        traced_node(f"{_AGENT}.remediate", _AGENT)(remediate),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_resources")
    graph.add_edge("scan_resources", "check_tags")
    graph.add_edge("check_tags", "evaluate_policies")
    graph.add_edge("evaluate_policies", "detect_violations")
    graph.add_conditional_edges(
        "detect_violations",
        _should_remediate,
        {
            "remediate": "remediate",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_governance_enforcer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Governance Enforcer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
