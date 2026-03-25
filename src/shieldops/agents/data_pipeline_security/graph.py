"""Data Pipeline Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataPipelineSecurityState
from .nodes import (
    assess_provenance,
    audit_data_flows,
    detect_poisoning,
    enforce_policies,
    generate_report,
    scan_rag_pipeline,
)
from .tools import DataPipelineSecurityToolkit


def _has_findings(state: Any) -> str:
    """Route based on whether any security findings were detected."""
    if hasattr(state, "model_dump"):
        d = state.model_dump()
    elif isinstance(state, dict):
        d = state
    else:
        d = dict(state)

    # Count anomalies that are not just baseline (info-level)
    real_anomalies = [
        a for a in d.get("data_flow_anomalies", []) if a.get("severity", "info") != "info"
    ]

    # Also count unverified provenance records
    unverified = [r for r in d.get("provenance_records", []) if not r.get("verified", True)]

    has_issues = (
        len(d.get("poisoning_findings", [])) > 0 or len(real_anomalies) > 0 or len(unverified) > 0
    )

    return "enforce_policies" if has_issues else "generate_report"


def build_graph(toolkit: DataPipelineSecurityToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Pipeline Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan_rag_pipeline(state: Any) -> dict[str, Any]:
        return await scan_rag_pipeline(_to_dict(state), toolkit)

    async def _audit_data_flows(state: Any) -> dict[str, Any]:
        return await audit_data_flows(_to_dict(state), toolkit)

    async def _detect_poisoning(state: Any) -> dict[str, Any]:
        return await detect_poisoning(_to_dict(state), toolkit)

    async def _assess_provenance(state: Any) -> dict[str, Any]:
        return await assess_provenance(_to_dict(state), toolkit)

    async def _enforce_policies(state: Any) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(DataPipelineSecurityState)

    # Add all nodes
    graph.add_node("scan_rag_pipeline", _scan_rag_pipeline)
    graph.add_node("audit_data_flows", _audit_data_flows)
    graph.add_node("detect_poisoning", _detect_poisoning)
    graph.add_node("assess_provenance", _assess_provenance)
    graph.add_node("enforce_policies", _enforce_policies)
    graph.add_node("generate_report", _generate_report)

    # Entry: sequential scanning pipeline
    graph.set_entry_point("scan_rag_pipeline")
    graph.add_edge("scan_rag_pipeline", "audit_data_flows")
    graph.add_edge("audit_data_flows", "detect_poisoning")
    graph.add_edge("detect_poisoning", "assess_provenance")

    # Conditional: if findings exist, enforce policies then report; else straight to report
    graph.add_conditional_edges(
        "assess_provenance",
        _has_findings,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )

    # If policies enforced, then generate report
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_data_pipeline_security_graph(
    vector_db_client: Any | None = None,
    model_registry: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Pipeline Security agent graph with dependencies."""
    toolkit = DataPipelineSecurityToolkit(
        vector_db_client=vector_db_client,
        model_registry=model_registry,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
