"""LangGraph workflow for the Cloud Workload Inspector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_workload_inspector.models import (
    CloudWorkloadInspectorState,
)
from shieldops.agents.cloud_workload_inspector.nodes import (
    analyze_config,
    assess_risk,
    check_compliance,
    discover_workloads,
    generate_report,
    recommend,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_workload_inspector"


def _should_analyze(
    state: CloudWorkloadInspectorState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "generate_report"
    if state.discovered_workloads:
        return "analyze_config"
    return "generate_report"


def _should_assess_risk(
    state: CloudWorkloadInspectorState,
) -> str:
    """Route after compliance check."""
    if state.compliance_pass_rate < 100.0:
        return "assess_risk"
    return "recommend"


def create_cloud_workload_inspector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Workload Inspector LangGraph.

    Workflow:
        discover_workloads
          -> [has_workloads?] -> analyze_config
          -> check_compliance
          -> [non_compliant?] -> assess_risk
          -> recommend
          -> generate_report
    """
    graph = StateGraph(CloudWorkloadInspectorState)

    graph.add_node(
        "discover_workloads",
        traced_node(
            f"{_AGENT}.discover_workloads",
            _AGENT,
        )(discover_workloads),
    )
    graph.add_node(
        "analyze_config",
        traced_node(
            f"{_AGENT}.analyze_config",
            _AGENT,
        )(analyze_config),
    )
    graph.add_node(
        "check_compliance",
        traced_node(
            f"{_AGENT}.check_compliance",
            _AGENT,
        )(check_compliance),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "recommend",
        traced_node(
            f"{_AGENT}.recommend",
            _AGENT,
        )(recommend),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_workloads")
    graph.add_conditional_edges(
        "discover_workloads",
        _should_analyze,
        {
            "analyze_config": "analyze_config",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_config", "check_compliance")
    graph.add_conditional_edges(
        "check_compliance",
        _should_assess_risk,
        {
            "assess_risk": "assess_risk",
            "recommend": "recommend",
        },
    )
    graph.add_edge("assess_risk", "recommend")
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
