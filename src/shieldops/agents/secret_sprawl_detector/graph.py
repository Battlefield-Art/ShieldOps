"""LangGraph workflow definition for the Secret Sprawl
Detector Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.secret_sprawl_detector.models import (
    SecretSprawlDetectorState,
)
from shieldops.agents.secret_sprawl_detector.nodes import (
    alert_owners,
    classify_risk,
    detect_secrets,
    generate_report,
    scan_config,
    scan_repos,
)
from shieldops.agents.tracing import traced_node

_AGENT = "secret_sprawl_detector"


def _should_alert(
    state: SecretSprawlDetectorState,
) -> str:
    """Route after classification: alert owners if
    secrets found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_secrets > 0:
        return "alert_owners"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Secret Sprawl Detector LangGraph
    workflow.

    Workflow:
        scan_repos -> scan_config -> detect_secrets
            -> classify_risk
            -> [secrets? -> alert_owners]
            -> generate_report -> END
    """
    graph = StateGraph(SecretSprawlDetectorState)

    graph.add_node(
        "scan_repos",
        traced_node(f"{_AGENT}.scan_repos", _AGENT)(scan_repos),
    )
    graph.add_node(
        "scan_config",
        traced_node(f"{_AGENT}.scan_config", _AGENT)(scan_config),
    )
    graph.add_node(
        "detect_secrets",
        traced_node(f"{_AGENT}.detect_secrets", _AGENT)(detect_secrets),
    )
    graph.add_node(
        "classify_risk",
        traced_node(f"{_AGENT}.classify_risk", _AGENT)(classify_risk),
    )
    graph.add_node(
        "alert_owners",
        traced_node(f"{_AGENT}.alert_owners", _AGENT)(alert_owners),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_repos")
    graph.add_edge("scan_repos", "scan_config")
    graph.add_edge("scan_config", "detect_secrets")
    graph.add_edge("detect_secrets", "classify_risk")
    graph.add_conditional_edges(
        "classify_risk",
        _should_alert,
        {
            "alert_owners": "alert_owners",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("alert_owners", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_secret_sprawl_detector_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Secret Sprawl Detector
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
