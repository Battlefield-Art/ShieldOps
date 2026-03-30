"""Cloud Workload Protector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudWorkloadProtectorState
from .nodes import (
    analyze_drift,
    assess_vulnerabilities,
    contain_threats,
    detect_anomalies,
    generate_report,
    scan_workloads,
)
from .tools import CloudWorkloadProtectorToolkit


def _should_contain(state: Any) -> str:
    """Route to containment if critical threats exist."""
    if isinstance(state, dict):
        anomalies = state.get("anomalies", [])
        vulns = state.get("vulnerabilities", [])
    else:
        anomalies = getattr(state, "anomalies", [])
        vulns = getattr(state, "vulnerabilities", [])

    # Check for critical/high anomalies
    for a in anomalies:
        sev = a.get("severity", "") if isinstance(a, dict) else getattr(a, "severity", "")
        if sev in ("critical", "high"):
            return "contain_threats"

    # Check for exploitable critical vulns
    for v in vulns:
        sev = v.get("severity", "") if isinstance(v, dict) else getattr(v, "severity", "")
        exploitable = (
            v.get("exploitable", False) if isinstance(v, dict) else getattr(v, "exploitable", False)
        )
        if sev == "critical" and exploitable:
            return "contain_threats"

    return "generate_report"


def build_graph(
    toolkit: CloudWorkloadProtectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Workload Protector agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_workloads(
            _to_dict(state),
            toolkit,
        )

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _drift(state: Any) -> dict[str, Any]:
        return await analyze_drift(
            _to_dict(state),
            toolkit,
        )

    async def _vulns(state: Any) -> dict[str, Any]:
        return await assess_vulnerabilities(
            _to_dict(state),
            toolkit,
        )

    async def _contain(state: Any) -> dict[str, Any]:
        return await contain_threats(
            _to_dict(state),
            toolkit,
        )

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(CloudWorkloadProtectorState)

    # Add nodes
    graph.add_node("scan_workloads", _scan)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("analyze_drift", _drift)
    graph.add_node("assess_vulnerabilities", _vulns)
    graph.add_node("contain_threats", _contain)
    graph.add_node("generate_report", _report)

    # Linear: scan -> detect -> drift -> vulns
    graph.set_entry_point("scan_workloads")
    graph.add_edge(
        "scan_workloads",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "analyze_drift",
    )
    graph.add_edge(
        "analyze_drift",
        "assess_vulnerabilities",
    )

    # Conditional: contain if threats, else report
    graph.add_conditional_edges(
        "assess_vulnerabilities",
        _should_contain,
        {
            "contain_threats": "contain_threats",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "contain_threats",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_workload_protector_graph(
    runtime_client: Any | None = None,
    vuln_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Workload Protector graph."""
    toolkit = CloudWorkloadProtectorToolkit(
        runtime_client=runtime_client,
        vuln_db=vuln_db,
    )
    return build_graph(toolkit)
