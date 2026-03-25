"""Container Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ContainerSecurityState, ImageSeverity, RuntimeThreat
from .nodes import (
    analyze_runtime,
    detect_anomalies,
    enforce_admission,
    generate_report,
    remediate,
    scan_images,
)
from .tools import ContainerSecurityToolkit

# Threat types that require immediate remediation
_CRITICAL_THREATS = {
    RuntimeThreat.REVERSE_SHELL.value,
    RuntimeThreat.CONTAINER_ESCAPE.value,
    RuntimeThreat.PRIVILEGE_ESCALATION.value,
}


def _has_threats(state: Any) -> str:
    """Route based on whether critical threats or vulnerabilities were found."""
    if hasattr(state, "runtime_anomalies"):
        anomalies = state.runtime_anomalies
        vulns = state.image_vulnerabilities
    else:
        anomalies = state.get("runtime_anomalies", [])
        vulns = state.get("image_vulnerabilities", [])

    # Check for critical runtime threats
    for a in anomalies:
        threat = a.get("threat_type", "") if isinstance(a, dict) else a.threat_type
        sev = a.get("severity", "") if isinstance(a, dict) else a.severity
        if threat in _CRITICAL_THREATS or sev in (
            ImageSeverity.CRITICAL.value,
            "critical",
        ):
            return "remediate"

    # Check for critical exploitable vulnerabilities
    for v in vulns:
        sev = v.get("severity", "") if isinstance(v, dict) else v.severity
        exploitable = v.get("exploitable", False) if isinstance(v, dict) else v.exploitable
        if sev in (ImageSeverity.CRITICAL.value, "critical") and exploitable:
            return "remediate"

    return "report"


def build_graph(
    toolkit: ContainerSecurityToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Container Security graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_images(_to_dict(state), toolkit)

    async def _runtime(state: Any) -> dict[str, Any]:
        return await analyze_runtime(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _admission(state: Any) -> dict[str, Any]:
        return await enforce_admission(_to_dict(state), toolkit)

    async def _remediate(state: Any) -> dict[str, Any]:
        return await remediate(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ContainerSecurityState)
    graph.add_node("scan_images", _scan)
    graph.add_node("analyze_runtime", _runtime)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("enforce_admission", _admission)
    graph.add_node("remediate", _remediate)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("scan_images")
    graph.add_edge("scan_images", "analyze_runtime")
    graph.add_edge("analyze_runtime", "detect_anomalies")
    graph.add_edge("detect_anomalies", "enforce_admission")
    graph.add_conditional_edges(
        "enforce_admission",
        _has_threats,
        {"remediate": "remediate", "report": "generate_report"},
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_container_security_graph(
    registry_client: Any | None = None,
    k8s_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Container Security graph with dependencies."""
    toolkit = ContainerSecurityToolkit(
        registry_client=registry_client,
        k8s_client=k8s_client,
    )
    return build_graph(toolkit)
