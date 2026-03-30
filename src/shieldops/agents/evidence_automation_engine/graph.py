"""Evidence Automation Engine Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import EvidenceAutomationEngineState
from .nodes import (
    collect_evidence,
    identify_requirements,
    package_evidence,
    report,
    submit_attestation,
    validate_artifacts,
)
from .tools import EvidenceAutomationEngineToolkit

_AGENT = "evidence_automation_engine"


def _check_error(
    state: EvidenceAutomationEngineState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: EvidenceAutomationEngineToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Evidence Automation Engine graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _identify(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_requirements(
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

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_artifacts(
            _to_dict(state),
            toolkit,
        )

    async def _package(
        state: Any,
    ) -> dict[str, Any]:
        return await package_evidence(
            _to_dict(state),
            toolkit,
        )

    async def _submit(
        state: Any,
    ) -> dict[str, Any]:
        return await submit_attestation(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(EvidenceAutomationEngineState)
    graph.add_node(
        "identify_requirements",
        traced_node("eae.identify", _AGENT)(_identify),
    )
    graph.add_node(
        "collect_evidence",
        traced_node("eae.collect", _AGENT)(_collect),
    )
    graph.add_node(
        "validate_artifacts",
        traced_node("eae.validate", _AGENT)(_validate),
    )
    graph.add_node(
        "package_evidence",
        traced_node("eae.package", _AGENT)(_package),
    )
    graph.add_node(
        "submit_attestation",
        traced_node("eae.submit", _AGENT)(_submit),
    )
    graph.add_node(
        "report",
        traced_node("eae.report", _AGENT)(_report),
    )

    graph.set_entry_point("identify_requirements")
    graph.add_edge(
        "identify_requirements",
        "collect_evidence",
    )
    graph.add_edge(
        "collect_evidence",
        "validate_artifacts",
    )
    graph.add_edge(
        "validate_artifacts",
        "package_evidence",
    )
    graph.add_edge(
        "package_evidence",
        "submit_attestation",
    )
    graph.add_edge("submit_attestation", "report")
    graph.add_edge("report", END)

    return graph


def create_evidence_automation_engine_graph(
    evidence_store: Any | None = None,
    scanner: Any | None = None,
    attestation_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Evidence Automation Engine graph."""
    toolkit = EvidenceAutomationEngineToolkit(
        evidence_store=evidence_store,
        scanner=scanner,
        attestation_api=attestation_api,
    )
    return build_graph(toolkit)
