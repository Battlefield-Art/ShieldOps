"""LangGraph workflow definition for the Data Privacy
Scanner Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.data_privacy_scanner.models import (
    DataPrivacyScannerState,
)
from shieldops.agents.data_privacy_scanner.nodes import (
    assess_compliance,
    classify_data,
    detect_pii,
    generate_report,
    map_flows,
    scan_datastores,
)
from shieldops.agents.tracing import traced_node

_AGENT = "data_privacy_scanner"


def _should_map_flows(
    state: DataPrivacyScannerState,
) -> str:
    """Route after PII detection: map flows if findings
    exist or on error, otherwise skip to compliance."""
    if state.error:
        return "generate_report"
    if state.pii_findings:
        return "map_flows"
    return "assess_compliance"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Privacy Scanner LangGraph workflow.

    Workflow:
        scan_datastores -> classify_data -> detect_pii
            -> [findings? -> map_flows]
            -> assess_compliance -> generate_report -> END
    """
    graph = StateGraph(DataPrivacyScannerState)

    graph.add_node(
        "scan_datastores",
        traced_node(f"{_AGENT}.scan_datastores", _AGENT)(scan_datastores),
    )
    graph.add_node(
        "classify_data",
        traced_node(f"{_AGENT}.classify_data", _AGENT)(classify_data),
    )
    graph.add_node(
        "detect_pii",
        traced_node(f"{_AGENT}.detect_pii", _AGENT)(detect_pii),
    )
    graph.add_node(
        "map_flows",
        traced_node(f"{_AGENT}.map_flows", _AGENT)(map_flows),
    )
    graph.add_node(
        "assess_compliance",
        traced_node(f"{_AGENT}.assess_compliance", _AGENT)(assess_compliance),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_datastores")
    graph.add_edge("scan_datastores", "classify_data")
    graph.add_edge("classify_data", "detect_pii")
    graph.add_conditional_edges(
        "detect_pii",
        _should_map_flows,
        {
            "map_flows": "map_flows",
            "assess_compliance": "assess_compliance",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("map_flows", "assess_compliance")
    graph.add_edge("assess_compliance", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_data_privacy_scanner_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Data Privacy Scanner graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
