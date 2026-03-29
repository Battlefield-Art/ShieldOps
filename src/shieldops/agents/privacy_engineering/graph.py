"""Privacy Engineering Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PrivacyEngineeringState
from .nodes import (
    assess_anonymization,
    audit_pets,
    check_compliance,
    report,
    scan_pipelines,
    validate_differential_privacy,
)
from .tools import PrivacyEngineeringToolkit


def _has_error(state: Any) -> str:
    """Route based on whether an error occurred."""
    error = state.error if hasattr(state, "error") else state.get("error", "")
    if error:
        return "report"
    return "continue"


def _has_findings(state: Any) -> str:
    """Route based on whether anonymization findings exist."""
    if hasattr(state, "anonymization_findings"):
        findings = state.anonymization_findings
    else:
        findings = state.get("anonymization_findings", [])
    if findings:
        return "validate"
    return "report"


def build_graph(
    toolkit: PrivacyEngineeringToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Privacy Engineering agent graph.

    Flow: scan_pipelines -> assess_anonymization -> (findings?) ->
          validate_differential_privacy -> audit_pets -> check_compliance -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_pipelines(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_anonymization(_to_dict(state), toolkit)

    async def _validate_dp(state: Any) -> dict[str, Any]:
        return await validate_differential_privacy(_to_dict(state), toolkit)

    async def _audit_pets(state: Any) -> dict[str, Any]:
        return await audit_pets(_to_dict(state), toolkit)

    async def _compliance(state: Any) -> dict[str, Any]:
        return await check_compliance(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(PrivacyEngineeringState)
    graph.add_node("scan_pipelines", _scan)
    graph.add_node("assess_anonymization", _assess)
    graph.add_node("validate_differential_privacy", _validate_dp)
    graph.add_node("audit_pets", _audit_pets)
    graph.add_node("check_compliance", _compliance)
    graph.add_node("report", _report)

    graph.set_entry_point("scan_pipelines")
    graph.add_conditional_edges(
        "scan_pipelines",
        _has_error,
        {"report": "report", "continue": "assess_anonymization"},
    )
    graph.add_conditional_edges(
        "assess_anonymization",
        _has_findings,
        {"validate": "validate_differential_privacy", "report": "report"},
    )
    graph.add_edge("validate_differential_privacy", "audit_pets")
    graph.add_edge("audit_pets", "check_compliance")
    graph.add_edge("check_compliance", "report")
    graph.add_edge("report", END)

    return graph


def create_privacy_engineering_graph(
    pipeline_registry: Any | None = None,
    pet_scanner: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Privacy Engineering graph with dependencies."""
    toolkit = PrivacyEngineeringToolkit(
        pipeline_registry=pipeline_registry,
        pet_scanner=pet_scanner,
    )
    return build_graph(toolkit)
