"""LangGraph workflow for the Service Health Monitor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.service_health_monitor.models import (
    ServiceHealthMonitorState,
)
from shieldops.agents.service_health_monitor.nodes import (
    analyze_dependencies,
    check_health,
    detect_degradation,
    discover_services,
    report,
    trigger_remediation,
)
from shieldops.agents.tracing import traced_node


def should_remediate(
    state: ServiceHealthMonitorState,
) -> str:
    """Route to remediation if degradation detected."""
    if state.error:
        return "report"
    if state.has_degradation:
        return "trigger_remediation"
    return "report"


def build_graph(
    **_kwargs: Any,
) -> StateGraph:
    """Build the Service Health Monitor StateGraph.

    Workflow:
        discover_services -> check_health
            -> analyze_dependencies
            -> detect_degradation
            -> [has_degradation? -> trigger_remediation]
            -> report
    """
    graph = StateGraph(ServiceHealthMonitorState)

    _agent = "service_health_monitor"
    graph.add_node(
        "discover_services",
        traced_node("shm.discover_services", _agent)(discover_services),
    )
    graph.add_node(
        "check_health",
        traced_node("shm.check_health", _agent)(check_health),
    )
    graph.add_node(
        "analyze_dependencies",
        traced_node("shm.analyze_dependencies", _agent)(analyze_dependencies),
    )
    graph.add_node(
        "detect_degradation",
        traced_node("shm.detect_degradation", _agent)(detect_degradation),
    )
    graph.add_node(
        "trigger_remediation",
        traced_node("shm.trigger_remediation", _agent)(trigger_remediation),
    )
    graph.add_node(
        "report",
        traced_node("shm.report", _agent)(report),
    )

    # Edges
    graph.set_entry_point("discover_services")
    graph.add_edge("discover_services", "check_health")
    graph.add_edge("check_health", "analyze_dependencies")
    graph.add_edge(
        "analyze_dependencies",
        "detect_degradation",
    )
    graph.add_conditional_edges(
        "detect_degradation",
        should_remediate,
        {
            "trigger_remediation": ("trigger_remediation"),
            "report": "report",
        },
    )
    graph.add_edge("trigger_remediation", "report")
    graph.add_edge("report", END)

    return graph


def create_service_health_monitor_graph(
    service_registry: Any | None = None,
    health_checker: Any | None = None,
    dependency_mapper: Any | None = None,
    remediation_engine: Any | None = None,
    notification_service: Any | None = None,
    policy_engine: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:
    """Factory to create a Service Health Monitor graph.

    Instantiates the toolkit, wires it into
    the module-level nodes, and builds the graph.
    """
    from shieldops.agents.service_health_monitor.nodes import (
        set_toolkit,
    )
    from shieldops.agents.service_health_monitor.tools import (
        ServiceHealthMonitorToolkit,
    )

    toolkit = ServiceHealthMonitorToolkit(
        service_registry=service_registry,
        health_checker=health_checker,
        dependency_mapper=dependency_mapper,
        remediation_engine=remediation_engine,
        notification_service=notification_service,
        policy_engine=policy_engine,
        repository=repository,
    )
    set_toolkit(toolkit)
    return build_graph()
