"""Compliance Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceScannerState
from .nodes import (
    evaluate_findings,
    generate_evidence,
    generate_report,
    scan_controls,
    select_frameworks,
    track_remediation,
)
from .tools import ComplianceScannerToolkit


def build_graph(toolkit: ComplianceScannerToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Scanner agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _select(state: Any) -> dict[str, Any]:
        return await select_frameworks(_to_dict(state), toolkit)

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_controls(_to_dict(state), toolkit)

    async def _evaluate(state: Any) -> dict[str, Any]:
        return await evaluate_findings(_to_dict(state), toolkit)

    async def _track(state: Any) -> dict[str, Any]:
        return await track_remediation(_to_dict(state), toolkit)

    async def _evidence(state: Any) -> dict[str, Any]:
        return await generate_evidence(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ComplianceScannerState)
    graph.add_node("select_frameworks", _select)
    graph.add_node("scan_controls", _scan)
    graph.add_node("evaluate_findings", _evaluate)
    graph.add_node("track_remediation", _track)
    graph.add_node("generate_evidence", _evidence)
    graph.add_node("report", _report)

    graph.set_entry_point("select_frameworks")
    graph.add_edge("select_frameworks", "scan_controls")
    graph.add_edge("scan_controls", "evaluate_findings")
    graph.add_edge("evaluate_findings", "track_remediation")
    graph.add_edge("track_remediation", "generate_evidence")
    graph.add_edge("generate_evidence", "report")
    graph.add_edge("report", END)

    return graph


def create_compliance_scanner_graph(
    policy_client: Any | None = None,
    config_client: Any | None = None,
    evidence_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Compliance Scanner agent graph with dependencies."""
    toolkit = ComplianceScannerToolkit(
        policy_client=policy_client,
        config_client=config_client,
        evidence_store=evidence_store,
    )
    return build_graph(toolkit)
