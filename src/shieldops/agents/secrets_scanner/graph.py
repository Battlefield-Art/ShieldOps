"""Secrets Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecretsScannerState
from .nodes import (
    classify_severity,
    detect_secrets,
    generate_report,
    remediate,
    scan_sources,
    verify_exposure,
)
from .tools import SecretsScannerToolkit


def _needs_remediation(state: Any) -> str:
    """Route based on whether active exposed secrets were found."""
    if hasattr(state, "secret_findings"):
        findings = state.secret_findings
    else:
        findings = state.get("secret_findings", [])

    for f in findings:
        is_active = f.get("is_active", False) if isinstance(f, dict) else f.is_active
        exposure = f.get("exposure_level", "unknown") if isinstance(f, dict) else f.exposure_level
        if is_active and exposure in ("public", "internal"):
            return "remediate"

    return "report"


def build_graph(toolkit: SecretsScannerToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Secrets Scanner graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan_sources(state: Any) -> dict[str, Any]:
        return await scan_sources(_to_dict(state), toolkit)

    async def _detect_secrets(state: Any) -> dict[str, Any]:
        return await detect_secrets(_to_dict(state), toolkit)

    async def _classify_severity(state: Any) -> dict[str, Any]:
        return await classify_severity(_to_dict(state), toolkit)

    async def _verify_exposure(state: Any) -> dict[str, Any]:
        return await verify_exposure(_to_dict(state), toolkit)

    async def _remediate(state: Any) -> dict[str, Any]:
        return await remediate(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SecretsScannerState)
    graph.add_node("scan_sources", _scan_sources)
    graph.add_node("detect_secrets", _detect_secrets)
    graph.add_node("classify_severity", _classify_severity)
    graph.add_node("verify_exposure", _verify_exposure)
    graph.add_node("remediate", _remediate)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("scan_sources")
    graph.add_edge("scan_sources", "detect_secrets")
    graph.add_edge("detect_secrets", "classify_severity")
    graph.add_edge("classify_severity", "verify_exposure")
    graph.add_conditional_edges(
        "verify_exposure",
        _needs_remediation,
        {"remediate": "remediate", "report": "generate_report"},
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_secrets_scanner_graph(
    git_client: Any | None = None,
    vault_client: Any | None = None,
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Secrets Scanner graph with dependencies."""
    toolkit = SecretsScannerToolkit(
        git_client=git_client,
        vault_client=vault_client,
        registry_client=registry_client,
    )
    return build_graph(toolkit)
