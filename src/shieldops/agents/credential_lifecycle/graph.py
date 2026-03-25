"""Credential Lifecycle Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CredentialLifecycleState
from .nodes import (
    assess_posture,
    discover_credentials,
    enforce_rotation,
    generate_report,
    issue_jit_credentials,
    revoke_stale,
)
from .tools import CredentialLifecycleToolkit


def _needs_remediation(state: Any) -> str:
    """Route based on whether stale or overprivileged credentials were found."""
    if hasattr(state, "model_dump"):
        d = state.model_dump()
    elif isinstance(state, dict):
        d = state
    else:
        d = dict(state)

    assessments = d.get("posture_assessments", [])

    has_issues = any(
        a.get("rating") in ("critical", "poor") or a.get("overprivileged") for a in assessments
    )

    return "issue_jit_credentials" if has_issues else "generate_report"


def build_graph(toolkit: CredentialLifecycleToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Credential Lifecycle agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover_credentials(state: Any) -> dict[str, Any]:
        return await discover_credentials(_to_dict(state), toolkit)

    async def _assess_posture(state: Any) -> dict[str, Any]:
        return await assess_posture(_to_dict(state), toolkit)

    async def _issue_jit_credentials(state: Any) -> dict[str, Any]:
        return await issue_jit_credentials(_to_dict(state), toolkit)

    async def _enforce_rotation(state: Any) -> dict[str, Any]:
        return await enforce_rotation(_to_dict(state), toolkit)

    async def _revoke_stale(state: Any) -> dict[str, Any]:
        return await revoke_stale(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CredentialLifecycleState)

    # Add all nodes
    graph.add_node("discover_credentials", _discover_credentials)
    graph.add_node("assess_posture", _assess_posture)
    graph.add_node("issue_jit_credentials", _issue_jit_credentials)
    graph.add_node("enforce_rotation", _enforce_rotation)
    graph.add_node("revoke_stale", _revoke_stale)
    graph.add_node("generate_report", _generate_report)

    # Entry: discover → assess
    graph.set_entry_point("discover_credentials")
    graph.add_edge("discover_credentials", "assess_posture")

    # Conditional: if stale/overprivileged found → remediation path; else → report
    graph.add_conditional_edges(
        "assess_posture",
        _needs_remediation,
        {
            "issue_jit_credentials": "issue_jit_credentials",
            "generate_report": "generate_report",
        },
    )

    # Remediation path: JIT → rotation → revocation → report
    graph.add_edge("issue_jit_credentials", "enforce_rotation")
    graph.add_edge("enforce_rotation", "revoke_stale")
    graph.add_edge("revoke_stale", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_credential_lifecycle_graph(
    vault_client: Any | None = None,
    iam_client: Any | None = None,
    secret_scanner: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Credential Lifecycle agent graph with dependencies."""
    toolkit = CredentialLifecycleToolkit(
        vault_client=vault_client,
        iam_client=iam_client,
        secret_scanner=secret_scanner,
    )
    return build_graph(toolkit)
