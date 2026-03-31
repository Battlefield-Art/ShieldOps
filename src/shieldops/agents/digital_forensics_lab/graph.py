"""LangGraph workflow definition for the Digital
Forensics Lab Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.digital_forensics_lab.models import (
    DigitalForensicsLabState,
)
from shieldops.agents.digital_forensics_lab.nodes import (
    acquire_evidence,
    analyze_artifacts,
    build_timeline,
    extract_iocs,
    generate_forensic_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "digital_forensics_lab"


def _should_build_timeline(
    state: DigitalForensicsLabState,
) -> str:
    """Route after IOC extraction: build timeline if IOCs
    exist or on error, otherwise skip to report."""
    if state.error:
        return "generate_forensic_report"
    if state.total_iocs > 0:
        return "build_timeline"
    return "generate_forensic_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Digital Forensics Lab LangGraph
    workflow.

    Workflow:
        acquire_evidence -> analyze_artifacts
            -> extract_iocs
            -> [iocs? -> build_timeline]
            -> generate_forensic_report -> END
    """
    graph = StateGraph(DigitalForensicsLabState)

    graph.add_node(
        "acquire_evidence",
        traced_node(f"{_AGENT}.acquire_evidence", _AGENT)(acquire_evidence),
    )
    graph.add_node(
        "analyze_artifacts",
        traced_node(f"{_AGENT}.analyze_artifacts", _AGENT)(analyze_artifacts),
    )
    graph.add_node(
        "extract_iocs",
        traced_node(f"{_AGENT}.extract_iocs", _AGENT)(extract_iocs),
    )
    graph.add_node(
        "build_timeline",
        traced_node(f"{_AGENT}.build_timeline", _AGENT)(build_timeline),
    )
    graph.add_node(
        "generate_forensic_report",
        traced_node(f"{_AGENT}.generate_forensic_report", _AGENT)(generate_forensic_report),
    )

    # Edges
    graph.set_entry_point("acquire_evidence")
    graph.add_edge("acquire_evidence", "analyze_artifacts")
    graph.add_edge("analyze_artifacts", "extract_iocs")
    graph.add_conditional_edges(
        "extract_iocs",
        _should_build_timeline,
        {
            "build_timeline": "build_timeline",
            "generate_forensic_report": "generate_forensic_report",
        },
    )
    graph.add_edge("build_timeline", "generate_forensic_report")
    graph.add_edge("generate_forensic_report", END)

    return graph


def create_digital_forensics_lab_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Digital Forensics Lab
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
