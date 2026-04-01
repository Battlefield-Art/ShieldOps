"""LangGraph workflow for the Cross-Cloud Posture Manager Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cross_cloud_posture_manager.models import (
    CrossCloudPostureManagerState,
)
from shieldops.agents.cross_cloud_posture_manager.nodes import (
    assess_compliance,
    compare_baselines,
    detect_drift,
    generate_report,
    plan_remediation,
    scan_posture,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cross_cloud_posture_manager"


def _should_detect_drift(
    state: CrossCloudPostureManagerState,
) -> str:
    """Route after baseline comparison."""
    if state.error:
        return "generate_report"
    if state.comparisons:
        return "detect_drift"
    return "generate_report"


def _should_plan(
    state: CrossCloudPostureManagerState,
) -> str:
    """Route after compliance assessment."""
    if state.compliance_gaps or state.drifts:
        return "plan_remediation"
    return "generate_report"


def create_cross_cloud_posture_manager_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Cross-Cloud Posture Manager LangGraph.

    Workflow:
        scan_posture -> compare_baselines
          -> [has_comparisons?] -> detect_drift -> assess_compliance
          -> [has_gaps_or_drifts?] -> plan_remediation -> generate_report
    """
    graph = StateGraph(CrossCloudPostureManagerState)

    graph.add_node(
        "scan_posture",
        traced_node(f"{_AGENT}.scan_posture", _AGENT)(scan_posture),
    )
    graph.add_node(
        "compare_baselines",
        traced_node(f"{_AGENT}.compare_baselines", _AGENT)(compare_baselines),
    )
    graph.add_node(
        "detect_drift",
        traced_node(f"{_AGENT}.detect_drift", _AGENT)(detect_drift),
    )
    graph.add_node(
        "assess_compliance",
        traced_node(f"{_AGENT}.assess_compliance", _AGENT)(assess_compliance),
    )
    graph.add_node(
        "plan_remediation",
        traced_node(f"{_AGENT}.plan_remediation", _AGENT)(plan_remediation),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("scan_posture")
    graph.add_edge("scan_posture", "compare_baselines")
    graph.add_conditional_edges(
        "compare_baselines",
        _should_detect_drift,
        {
            "detect_drift": "detect_drift",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_drift", "assess_compliance")
    graph.add_conditional_edges(
        "assess_compliance",
        _should_plan,
        {
            "plan_remediation": "plan_remediation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("plan_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
