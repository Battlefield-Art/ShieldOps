"""LangGraph workflow for the Runtime Protection Engine."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.runtime_protection_engine.models import (
    RuntimeProtectionEngineState,
)
from shieldops.agents.runtime_protection_engine.nodes import (
    analyze_behavior,
    collect_telemetry,
    detect_anomalies,
    enforce_policies,
    generate_alerts,
    generate_report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "runtime_protection_engine"


def should_enforce_policies(
    state: RuntimeProtectionEngineState,
) -> str:
    """Route: enforce policies if anomalies detected, else skip to report."""
    if state.error:
        return "generate_report"
    if state.anomaly_count > 0:
        return "enforce_policies"
    return "generate_report"


def should_generate_alerts(
    state: RuntimeProtectionEngineState,
) -> str:
    """Route: generate alerts if enforcement actions taken."""
    if state.error:
        return "generate_report"
    if state.enforcements:
        return "generate_alerts"
    return "generate_report"


def create_runtime_protection_engine_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Runtime Protection Engine LangGraph workflow.

    Workflow:
        collect_telemetry
        -> analyze_behavior
        -> detect_anomalies
        -> [anomalies? -> enforce_policies]
        -> [enforcements? -> generate_alerts]
        -> generate_report
        -> END
    """
    graph = StateGraph(RuntimeProtectionEngineState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "collect_telemetry",
        traced_node(
            f"{_AGENT}.collect_telemetry",
            _AGENT,
        )(collect_telemetry),
    )
    graph.add_node(
        "analyze_behavior",
        traced_node(
            f"{_AGENT}.analyze_behavior",
            _AGENT,
        )(analyze_behavior),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(
            f"{_AGENT}.detect_anomalies",
            _AGENT,
        )(detect_anomalies),
    )
    graph.add_node(
        "enforce_policies",
        traced_node(
            f"{_AGENT}.enforce_policies",
            _AGENT,
        )(enforce_policies),
    )
    graph.add_node(
        "generate_alerts",
        traced_node(
            f"{_AGENT}.generate_alerts",
            _AGENT,
        )(generate_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_telemetry")
    graph.add_edge("collect_telemetry", "analyze_behavior")
    graph.add_edge("analyze_behavior", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        should_enforce_policies,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "enforce_policies",
        should_generate_alerts,
        {
            "generate_alerts": "generate_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
