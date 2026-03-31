"""LangGraph workflow for the Cloud Drift Remediator."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_drift_remediator.models import (
    CloudDriftRemediatorState,
)
from shieldops.agents.cloud_drift_remediator.nodes import (
    classify_risk,
    detect_drift,
    execute_fix,
    generate_report,
    plan_remediation,
    scan_baseline,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_drift_remediator"


def _should_detect(
    state: CloudDriftRemediatorState,
) -> str:
    """Route after baseline scan."""
    if state.error:
        return "generate_report"
    if state.baseline_resources:
        return "detect_drift"
    return "generate_report"


def _should_execute(
    state: CloudDriftRemediatorState,
) -> str:
    """Route after remediation planning."""
    if state.remediation_plans:
        return "execute_fix"
    return "generate_report"


def create_cloud_drift_remediator_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Drift Remediator LangGraph.

    Workflow:
        scan_baseline
          -> [has_resources?] -> detect_drift
          -> classify_risk
          -> plan_remediation
          -> [has_plans?] -> execute_fix
          -> generate_report
    """
    graph = StateGraph(CloudDriftRemediatorState)

    graph.add_node(
        "scan_baseline",
        traced_node(
            f"{_AGENT}.scan_baseline",
            _AGENT,
        )(scan_baseline),
    )
    graph.add_node(
        "detect_drift",
        traced_node(
            f"{_AGENT}.detect_drift",
            _AGENT,
        )(detect_drift),
    )
    graph.add_node(
        "classify_risk",
        traced_node(
            f"{_AGENT}.classify_risk",
            _AGENT,
        )(classify_risk),
    )
    graph.add_node(
        "plan_remediation",
        traced_node(
            f"{_AGENT}.plan_remediation",
            _AGENT,
        )(plan_remediation),
    )
    graph.add_node(
        "execute_fix",
        traced_node(
            f"{_AGENT}.execute_fix",
            _AGENT,
        )(execute_fix),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_baseline")
    graph.add_conditional_edges(
        "scan_baseline",
        _should_detect,
        {
            "detect_drift": "detect_drift",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_drift", "classify_risk")
    graph.add_edge("classify_risk", "plan_remediation")
    graph.add_conditional_edges(
        "plan_remediation",
        _should_execute,
        {
            "execute_fix": "execute_fix",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("execute_fix", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
