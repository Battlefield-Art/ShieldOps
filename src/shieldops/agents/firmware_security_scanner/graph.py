"""LangGraph workflow for the Firmware Security Scanner Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.firmware_security_scanner.models import (
    FirmwareSecurityScannerState,
)
from shieldops.agents.firmware_security_scanner.nodes import (
    analyze_components,
    assess_risk,
    check_crypto,
    extract_firmware,
    generate_report,
    scan_vulnerabilities,
)
from shieldops.agents.tracing import traced_node

_AGENT = "firmware_security_scanner"


def _should_analyze(
    state: FirmwareSecurityScannerState,
) -> str:
    """Route after extraction based on results."""
    if state.error:
        return "generate_report"
    if state.firmware_images:
        return "analyze_components"
    return "generate_report"


def _should_check_crypto(
    state: FirmwareSecurityScannerState,
) -> str:
    """Route after vulnerability scanning."""
    if state.critical_vuln_count > 0:
        return "check_crypto"
    return "check_crypto"


def create_firmware_security_scanner_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Firmware Security Scanner LangGraph.

    Workflow:
        extract_firmware
          -> [has_images?] -> analyze_components
          -> scan_vulnerabilities
          -> check_crypto
          -> assess_risk
          -> generate_report
    """
    graph = StateGraph(FirmwareSecurityScannerState)

    graph.add_node(
        "extract_firmware",
        traced_node(
            f"{_AGENT}.extract_firmware",
            _AGENT,
        )(extract_firmware),
    )
    graph.add_node(
        "analyze_components",
        traced_node(
            f"{_AGENT}.analyze_components",
            _AGENT,
        )(analyze_components),
    )
    graph.add_node(
        "scan_vulnerabilities",
        traced_node(
            f"{_AGENT}.scan_vulnerabilities",
            _AGENT,
        )(scan_vulnerabilities),
    )
    graph.add_node(
        "check_crypto",
        traced_node(
            f"{_AGENT}.check_crypto",
            _AGENT,
        )(check_crypto),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("extract_firmware")
    graph.add_conditional_edges(
        "extract_firmware",
        _should_analyze,
        {
            "analyze_components": "analyze_components",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_components", "scan_vulnerabilities")
    graph.add_conditional_edges(
        "scan_vulnerabilities",
        _should_check_crypto,
        {
            "check_crypto": "check_crypto",
        },
    )
    graph.add_edge("check_crypto", "assess_risk")
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
