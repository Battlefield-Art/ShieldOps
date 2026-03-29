"""Deepfake Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DeepfakeDetectorState
from .nodes import (
    analyze_artifacts,
    check_provenance,
    classify_authenticity,
    generate_evidence,
    generate_report,
    ingest_media,
)
from .tools import DeepfakeDetectorToolkit


def _has_synthetic(state: Any) -> str:
    """Route: generate evidence only if synthetic media detected."""
    if hasattr(state, "classifications"):
        classifications = state.classifications
    else:
        classifications = state.get("classifications", [])

    for c in classifications:
        verdict = c.get("verdict", "") if isinstance(c, dict) else c.verdict
        if verdict in (
            "synthetic",
            "likely_synthetic",
        ):
            return "generate_evidence"

    return "report"


def _has_error(state: Any) -> str:
    """Route: skip to report on error."""
    error = state.error if hasattr(state, "error") else state.get("error", "")

    if error:
        return "report"
    return "continue"


def build_graph(
    toolkit: DeepfakeDetectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Deepfake Detector graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_media(_to_dict(state), toolkit)

    async def _artifacts(state: Any) -> dict[str, Any]:
        return await analyze_artifacts(_to_dict(state), toolkit)

    async def _provenance(state: Any) -> dict[str, Any]:
        return await check_provenance(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_authenticity(_to_dict(state), toolkit)

    async def _evidence(state: Any) -> dict[str, Any]:
        return await generate_evidence(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(DeepfakeDetectorState)
    graph.add_node("ingest_media", _ingest)
    graph.add_node("analyze_artifacts", _artifacts)
    graph.add_node("check_provenance", _provenance)
    graph.add_node("classify_authenticity", _classify)
    graph.add_node("generate_evidence", _evidence)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("ingest_media")

    # Error routing after ingest
    graph.add_conditional_edges(
        "ingest_media",
        _has_error,
        {
            "report": "generate_report",
            "continue": "analyze_artifacts",
        },
    )
    graph.add_edge("analyze_artifacts", "check_provenance")
    graph.add_edge("check_provenance", "classify_authenticity")

    # Conditional: generate evidence only for synthetic detections
    graph.add_conditional_edges(
        "classify_authenticity",
        _has_synthetic,
        {
            "generate_evidence": "generate_evidence",
            "report": "generate_report",
        },
    )
    graph.add_edge("generate_evidence", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_deepfake_detector_graph(
    c2pa_client: Any | None = None,
    forensics_client: Any | None = None,
    model_detector_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Deepfake Detector graph."""
    toolkit = DeepfakeDetectorToolkit(
        c2pa_client=c2pa_client,
        forensics_client=forensics_client,
        model_detector_client=model_detector_client,
    )
    return build_graph(toolkit)
