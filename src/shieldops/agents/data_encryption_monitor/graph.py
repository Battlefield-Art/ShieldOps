"""Data Encryption Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataEncryptionMonitorState
from .nodes import (
    assess_encryption,
    check_certificates,
    check_key_rotation,
    identify_gaps,
    report,
    scan_assets,
)
from .tools import DataEncryptionMonitorToolkit


def _has_gaps(state: Any) -> str:
    """Route based on whether encryption gaps exist."""
    if hasattr(state, "encryption_gaps"):
        gaps = state.encryption_gaps
    else:
        gaps = state.get("encryption_gaps", [])
    if gaps:
        return "report"
    return "report"


def build_graph(
    toolkit: DataEncryptionMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Encryption Monitor agent graph.

    Flow: scan_assets -> assess_encryption
          -> check_key_rotation -> check_certificates
          -> identify_gaps -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_assets(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_encryption(_to_dict(state), toolkit)

    async def _keys(state: Any) -> dict[str, Any]:
        return await check_key_rotation(_to_dict(state), toolkit)

    async def _certs(state: Any) -> dict[str, Any]:
        return await check_certificates(_to_dict(state), toolkit)

    async def _gaps(state: Any) -> dict[str, Any]:
        return await identify_gaps(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    # Traced node wrappers
    traced_scan = _scan
    traced_assess = _assess
    traced_keys = _keys
    traced_certs = _certs
    traced_gaps = _gaps
    traced_report = _report

    graph = StateGraph(DataEncryptionMonitorState)
    graph.add_node("scan_assets", traced_scan)
    graph.add_node("assess_encryption", traced_assess)
    graph.add_node("check_key_rotation", traced_keys)
    graph.add_node("check_certificates", traced_certs)
    graph.add_node("identify_gaps", traced_gaps)
    graph.add_node("report", traced_report)

    graph.set_entry_point("scan_assets")
    graph.add_edge("scan_assets", "assess_encryption")
    graph.add_edge("assess_encryption", "check_key_rotation")
    graph.add_edge("check_key_rotation", "check_certificates")
    graph.add_edge("check_certificates", "identify_gaps")
    graph.add_edge("identify_gaps", "report")
    graph.add_edge("report", END)

    return graph


def create_data_encryption_monitor_graph(
    aws_connector: Any | None = None,
    gcp_connector: Any | None = None,
    azure_connector: Any | None = None,
    vault_connector: Any | None = None,
    certificate_connector: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the encryption monitor graph with dependencies."""
    toolkit = DataEncryptionMonitorToolkit(
        aws_connector=aws_connector,
        gcp_connector=gcp_connector,
        azure_connector=azure_connector,
        vault_connector=vault_connector,
        certificate_connector=certificate_connector,
    )
    return build_graph(toolkit)
