"""LangGraph workflow for the Container Runtime Protector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.container_runtime_protector.models import (
    ContainerRuntimeProtectorState,
)
from shieldops.agents.container_runtime_protector.nodes import (
    analyze_syscalls,
    detect_drift,
    enforce_policy,
    generate_report,
    monitor_runtime,
    profile_workload,
)
from shieldops.agents.tracing import traced_node

_AGENT = "container_runtime_protector"


def _should_monitor(
    state: ContainerRuntimeProtectorState,
) -> str:
    """Route after profiling based on results."""
    if state.error:
        return "generate_report"
    if state.workload_profiles:
        return "monitor_runtime"
    return "generate_report"


def _should_enforce(
    state: ContainerRuntimeProtectorState,
) -> str:
    """Route after syscall analysis based on risk."""
    if state.max_risk_score > 40.0:
        return "enforce_policy"
    return "generate_report"


def create_container_runtime_protector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Container Runtime Protector LangGraph.

    Workflow:
        profile_workload
          -> [has_workloads?] -> monitor_runtime
          -> detect_drift
          -> analyze_syscalls
          -> [high_risk?] -> enforce_policy
          -> generate_report
    """
    graph = StateGraph(ContainerRuntimeProtectorState)

    graph.add_node(
        "profile_workload",
        traced_node(
            f"{_AGENT}.profile_workload",
            _AGENT,
        )(profile_workload),
    )
    graph.add_node(
        "monitor_runtime",
        traced_node(
            f"{_AGENT}.monitor_runtime",
            _AGENT,
        )(monitor_runtime),
    )
    graph.add_node(
        "detect_drift",
        traced_node(
            f"{_AGENT}.detect_drift",
            _AGENT,
        )(detect_drift),
    )
    graph.add_node(
        "analyze_syscalls",
        traced_node(
            f"{_AGENT}.analyze_syscalls",
            _AGENT,
        )(analyze_syscalls),
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
    graph.set_entry_point("profile_workload")
    graph.add_conditional_edges(
        "profile_workload",
        _should_monitor,
        {
            "monitor_runtime": "monitor_runtime",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("monitor_runtime", "detect_drift")
    graph.add_edge("detect_drift", "analyze_syscalls")
    graph.add_conditional_edges(
        "analyze_syscalls",
        _should_enforce,
        {
            "enforce_policy": "enforce_policy",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policy", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
