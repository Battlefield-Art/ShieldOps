"""CI/CD Security Auditor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ci_cd_security_auditor.models import CiCdSecurityAuditorState
from shieldops.agents.ci_cd_security_auditor.nodes import (
    assess_risk,
    check_permissions,
    detect_injection,
    map_pipelines,
    report,
    scan_configs,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ci_cd_security_auditor"


def _check_error(state: CiCdSecurityAuditorState) -> str:
    return "report" if state.error else "next"


def create_ci_cd_security_auditor_graph() -> StateGraph:
    """Build the CI/CD Security Auditor workflow."""
    graph = StateGraph(CiCdSecurityAuditorState)

    graph.add_node(
        "map_pipelines",
        traced_node(f"{_AGENT}.map_pipelines", _AGENT)(map_pipelines),
    )
    graph.add_node(
        "check_permissions",
        traced_node(f"{_AGENT}.check_permissions", _AGENT)(check_permissions),
    )
    graph.add_node(
        "scan_configs",
        traced_node(f"{_AGENT}.scan_configs", _AGENT)(scan_configs),
    )
    graph.add_node(
        "detect_injection",
        traced_node(f"{_AGENT}.detect_injection", _AGENT)(detect_injection),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("map_pipelines")

    graph.add_conditional_edges(
        "map_pipelines",
        _check_error,
        {"next": "check_permissions", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_permissions",
        _check_error,
        {"next": "scan_configs", "report": "report"},
    )
    graph.add_conditional_edges(
        "scan_configs",
        _check_error,
        {"next": "detect_injection", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_injection",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_edge("assess_risk", "report")
    graph.add_edge("report", END)

    return graph
