"""LangGraph workflow for the Compliance Drift Monitor Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.compliance_drift_monitor.models import (
    ComplianceDriftMonitorState,
)
from shieldops.agents.compliance_drift_monitor.nodes import (
    assess_impact,
    detect_drift,
    generate_report,
    load_baselines,
    plan_remediation,
    scan_current_state,
)
from shieldops.agents.tracing import traced_node

_AGENT = "compliance_drift_monitor"


def _should_assess(
    state: ComplianceDriftMonitorState,
) -> str:
    """Route after drift detection."""
    if state.error:
        return "generate_report"
    if state.drift_findings:
        return "assess_impact"
    return "generate_report"


def _should_remediate(
    state: ComplianceDriftMonitorState,
) -> str:
    """Route after impact assessment."""
    if state.impact_assessments:
        return "plan_remediation"
    return "generate_report"


def create_compliance_drift_monitor_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Drift Monitor LangGraph.

    Workflow:
        load_baselines -> scan_current_state -> detect_drift
          -> [has_drifts?] -> assess_impact
          -> [has_impacts?] -> plan_remediation
          -> generate_report
    """
    graph = StateGraph(ComplianceDriftMonitorState)

    graph.add_node(
        "load_baselines",
        traced_node(f"{_AGENT}.load_baselines", _AGENT)(load_baselines),
    )
    graph.add_node(
        "scan_current_state",
        traced_node(f"{_AGENT}.scan_current_state", _AGENT)(scan_current_state),
    )
    graph.add_node(
        "detect_drift",
        traced_node(f"{_AGENT}.detect_drift", _AGENT)(detect_drift),
    )
    graph.add_node(
        "assess_impact",
        traced_node(f"{_AGENT}.assess_impact", _AGENT)(assess_impact),
    )
    graph.add_node(
        "plan_remediation",
        traced_node(f"{_AGENT}.plan_remediation", _AGENT)(plan_remediation),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("load_baselines")
    graph.add_edge("load_baselines", "scan_current_state")
    graph.add_edge("scan_current_state", "detect_drift")
    graph.add_conditional_edges(
        "detect_drift",
        _should_assess,
        {
            "assess_impact": "assess_impact",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "assess_impact",
        _should_remediate,
        {
            "plan_remediation": "plan_remediation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("plan_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
