"""LangGraph workflow definition for the ML Model
Scanner Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.ml_model_scanner.models import (
    MLModelScannerState,
)
from shieldops.agents.ml_model_scanner.nodes import (
    assess_risk,
    check_provenance,
    detect_backdoors,
    discover_models,
    generate_report,
    scan_artifacts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ml_model_scanner"


def _should_detect_backdoors(
    state: MLModelScannerState,
) -> str:
    """Route after provenance: detect backdoors if scan
    results exist or on error, otherwise skip to risk."""
    if state.error:
        return "generate_report"
    if state.scan_results:
        return "detect_backdoors"
    return "assess_risk"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the ML Model Scanner LangGraph workflow.

    Workflow:
        discover_models -> scan_artifacts
            -> check_provenance
            -> [scan_results? -> detect_backdoors]
            -> assess_risk -> generate_report -> END
    """
    graph = StateGraph(MLModelScannerState)

    graph.add_node(
        "discover_models",
        traced_node(f"{_AGENT}.discover_models", _AGENT)(discover_models),
    )
    graph.add_node(
        "scan_artifacts",
        traced_node(f"{_AGENT}.scan_artifacts", _AGENT)(scan_artifacts),
    )
    graph.add_node(
        "check_provenance",
        traced_node(f"{_AGENT}.check_provenance", _AGENT)(check_provenance),
    )
    graph.add_node(
        "detect_backdoors",
        traced_node(f"{_AGENT}.detect_backdoors", _AGENT)(detect_backdoors),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_models")
    graph.add_edge("discover_models", "scan_artifacts")
    graph.add_edge("scan_artifacts", "check_provenance")
    graph.add_conditional_edges(
        "check_provenance",
        _should_detect_backdoors,
        {
            "detect_backdoors": "detect_backdoors",
            "assess_risk": "assess_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_backdoors", "assess_risk")
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_ml_model_scanner_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an ML Model Scanner graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
