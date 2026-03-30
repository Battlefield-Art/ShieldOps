"""Compliance Workflow Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceWorkflowState
from .nodes import (
    assess_gaps,
    collect_evidence,
    generate_remediation,
    generate_report,
    identify_frameworks,
    map_controls,
)
from .tools import ComplianceWorkflowToolkit


def build_graph(
    toolkit: ComplianceWorkflowToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Workflow agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _identify(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_frameworks(
            _to_dict(state),
            toolkit,
        )

    async def _map(state: Any) -> dict[str, Any]:
        return await map_controls(
            _to_dict(state),
            toolkit,
        )

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_evidence(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_gaps(
            _to_dict(state),
            toolkit,
        )

    async def _remediate(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_remediation(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(ComplianceWorkflowState)
    graph.add_node("identify_frameworks", _identify)
    graph.add_node("map_controls", _map)
    graph.add_node("collect_evidence", _collect)
    graph.add_node("assess_gaps", _assess)
    graph.add_node("generate_remediation", _remediate)
    graph.add_node("report", _report)

    graph.set_entry_point("identify_frameworks")
    graph.add_edge(
        "identify_frameworks",
        "map_controls",
    )
    graph.add_edge(
        "map_controls",
        "collect_evidence",
    )
    graph.add_edge(
        "collect_evidence",
        "assess_gaps",
    )
    graph.add_edge(
        "assess_gaps",
        "generate_remediation",
    )
    graph.add_edge("generate_remediation", "report")
    graph.add_edge("report", END)

    return graph


def create_compliance_workflow_graph(
    compliance_backend: Any | None = None,
    evidence_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create a Compliance Workflow graph."""
    toolkit = ComplianceWorkflowToolkit(
        compliance_backend=compliance_backend,
        evidence_store=evidence_store,
    )
    return build_graph(toolkit)
