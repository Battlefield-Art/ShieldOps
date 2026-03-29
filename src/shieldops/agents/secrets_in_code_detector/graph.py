"""Secrets in Code Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecretsInCodeDetectorState
from .nodes import (
    assess_exposure,
    discover_repositories,
    generate_report,
    prioritize_findings,
    scan_patterns,
    verify_secrets,
)
from .tools import SecretsInCodeDetectorToolkit


def build_graph(
    toolkit: SecretsInCodeDetectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Secrets in Code Detector LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_repositories(_to_dict(state), toolkit)

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_patterns(_to_dict(state), toolkit)

    async def _verify(state: Any) -> dict[str, Any]:
        return await verify_secrets(_to_dict(state), toolkit)

    async def _exposure(state: Any) -> dict[str, Any]:
        return await assess_exposure(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_findings(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SecretsInCodeDetectorState)
    graph.add_node("discover_repositories", _discover)
    graph.add_node("scan_patterns", _scan)
    graph.add_node("verify_secrets", _verify)
    graph.add_node("assess_exposure", _exposure)
    graph.add_node("prioritize", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_repositories")
    graph.add_edge("discover_repositories", "scan_patterns")
    graph.add_edge("scan_patterns", "verify_secrets")
    graph.add_edge("verify_secrets", "assess_exposure")
    graph.add_edge("assess_exposure", "prioritize")
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_secrets_in_code_detector_graph(
    git_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Secrets in Code Detector graph with deps."""
    toolkit = SecretsInCodeDetectorToolkit(
        git_client=git_client,
    )
    return build_graph(toolkit)
