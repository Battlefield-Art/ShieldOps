"""LangGraph workflow for the Credential Hygiene Auditor."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.credential_hygiene_auditor.models import (
    CredentialHygieneAuditorState,
)
from shieldops.agents.credential_hygiene_auditor.nodes import (
    assess_hygiene,
    detect_violations,
    generate_report,
    inventory_credentials,
    recommend_fixes,
    score_risk,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "credential_hygiene_auditor"


def _check_error(
    state: CredentialHygieneAuditorState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "generate_report"
    return "next"


def should_recommend_fixes(
    state: CredentialHygieneAuditorState,
) -> str:
    """Route: recommend fixes if violations found."""
    if state.error:
        return "generate_report"
    if state.violations:
        return "recommend_fixes"
    return "generate_report"


def create_credential_hygiene_auditor_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Credential Hygiene Auditor LangGraph workflow.

    Workflow:
        inventory_credentials
        -> assess_hygiene
        -> detect_violations
        -> score_risk
        -> [violations? -> recommend_fixes]
        -> generate_report
        -> END
    """
    graph = StateGraph(CredentialHygieneAuditorState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "inventory_credentials",
        traced_node(
            f"{_AGENT}.inventory_credentials",
            _AGENT,
        )(inventory_credentials),
    )
    graph.add_node(
        "assess_hygiene",
        traced_node(
            f"{_AGENT}.assess_hygiene",
            _AGENT,
        )(assess_hygiene),
    )
    graph.add_node(
        "detect_violations",
        traced_node(
            f"{_AGENT}.detect_violations",
            _AGENT,
        )(detect_violations),
    )
    graph.add_node(
        "score_risk",
        traced_node(
            f"{_AGENT}.score_risk",
            _AGENT,
        )(score_risk),
    )
    graph.add_node(
        "recommend_fixes",
        traced_node(
            f"{_AGENT}.recommend_fixes",
            _AGENT,
        )(recommend_fixes),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("inventory_credentials")
    graph.add_conditional_edges(
        "inventory_credentials",
        _check_error,
        {
            "next": "assess_hygiene",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "assess_hygiene",
        _check_error,
        {
            "next": "detect_violations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("detect_violations", "score_risk")
    graph.add_conditional_edges(
        "score_risk",
        should_recommend_fixes,
        {
            "recommend_fixes": "recommend_fixes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_fixes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
