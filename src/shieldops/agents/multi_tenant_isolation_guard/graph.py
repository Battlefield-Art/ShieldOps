"""LangGraph workflow for the Multi-Tenant Isolation Guard."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.multi_tenant_isolation_guard.models import (
    MultiTenantIsolationGuardState,
)
from shieldops.agents.multi_tenant_isolation_guard.nodes import (
    assess_isolation,
    detect_leakage,
    enforce_controls,
    generate_report,
    map_tenants,
    scan_boundaries,
)
from shieldops.agents.tracing import traced_node

_AGENT = "multi_tenant_isolation_guard"


def _should_detect(
    state: MultiTenantIsolationGuardState,
) -> str:
    if state.error:
        return "generate_report"
    if state.boundary_scans:
        return "detect_leakage"
    return "generate_report"


def _should_enforce(
    state: MultiTenantIsolationGuardState,
) -> str:
    if state.isolation_assessments:
        return "enforce_controls"
    return "generate_report"


def create_multi_tenant_isolation_guard_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Multi-Tenant Isolation Guard LangGraph.

    Workflow:
        map_tenants -> scan_boundaries
          -> [has_scans?] -> detect_leakage -> assess_isolation
          -> [has_assessments?] -> enforce_controls
          -> generate_report
    """
    graph = StateGraph(MultiTenantIsolationGuardState)

    graph.add_node(
        "map_tenants",
        traced_node(f"{_AGENT}.map_tenants", _AGENT)(
            map_tenants,
        ),
    )
    graph.add_node(
        "scan_boundaries",
        traced_node(f"{_AGENT}.scan_boundaries", _AGENT)(
            scan_boundaries,
        ),
    )
    graph.add_node(
        "detect_leakage",
        traced_node(f"{_AGENT}.detect_leakage", _AGENT)(
            detect_leakage,
        ),
    )
    graph.add_node(
        "assess_isolation",
        traced_node(f"{_AGENT}.assess_isolation", _AGENT)(
            assess_isolation,
        ),
    )
    graph.add_node(
        "enforce_controls",
        traced_node(f"{_AGENT}.enforce_controls", _AGENT)(
            enforce_controls,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("map_tenants")
    graph.add_edge("map_tenants", "scan_boundaries")
    graph.add_conditional_edges(
        "scan_boundaries",
        _should_detect,
        {
            "detect_leakage": "detect_leakage",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_leakage", "assess_isolation")
    graph.add_conditional_edges(
        "assess_isolation",
        _should_enforce,
        {
            "enforce_controls": "enforce_controls",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_controls", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
