"""LangGraph workflow for the Browser Threat Protector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.browser_threat_protector.models import (
    BrowserThreatProtectorState,
)
from shieldops.agents.browser_threat_protector.nodes import (
    analyze_request,
    check_reputation,
    enforce_policy,
    generate_report,
    isolate_session,
    scan_content,
)
from shieldops.agents.tracing import traced_node

_AGENT = "browser_threat_protector"


def _should_isolate(
    state: BrowserThreatProtectorState,
) -> str:
    """Route after reputation check based on results."""
    if state.error:
        return "generate_report"
    if state.suspicious_count > 0:
        return "isolate_session"
    return "enforce_policy"


def _should_scan(
    state: BrowserThreatProtectorState,
) -> str:
    """Route after isolation — scan if sessions exist."""
    if state.isolated_count > 0:
        return "scan_content"
    return "enforce_policy"


def create_browser_threat_protector_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Browser Threat Protector LangGraph.

    Workflow:
        analyze_request
          -> check_reputation
          -> [suspicious?] -> isolate_session
          -> [isolated?] -> scan_content
          -> enforce_policy
          -> generate_report
    """
    graph = StateGraph(BrowserThreatProtectorState)

    graph.add_node(
        "analyze_request",
        traced_node(
            f"{_AGENT}.analyze_request",
            _AGENT,
        )(analyze_request),
    )
    graph.add_node(
        "check_reputation",
        traced_node(
            f"{_AGENT}.check_reputation",
            _AGENT,
        )(check_reputation),
    )
    graph.add_node(
        "isolate_session",
        traced_node(
            f"{_AGENT}.isolate_session",
            _AGENT,
        )(isolate_session),
    )
    graph.add_node(
        "scan_content",
        traced_node(
            f"{_AGENT}.scan_content",
            _AGENT,
        )(scan_content),
    )
    graph.add_node(
        "enforce_policy",
        traced_node(
            f"{_AGENT}.enforce_policy",
            _AGENT,
        )(enforce_policy),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("analyze_request")
    graph.add_edge("analyze_request", "check_reputation")
    graph.add_conditional_edges(
        "check_reputation",
        _should_isolate,
        {
            "isolate_session": "isolate_session",
            "enforce_policy": "enforce_policy",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "isolate_session",
        _should_scan,
        {
            "scan_content": "scan_content",
            "enforce_policy": "enforce_policy",
        },
    )
    graph.add_edge("scan_content", "enforce_policy")
    graph.add_edge("enforce_policy", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
