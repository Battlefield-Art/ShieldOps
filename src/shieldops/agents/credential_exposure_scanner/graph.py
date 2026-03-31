"""Credential Exposure Scanner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CredentialExposureScannerState
from .nodes import (
    assess_exposure,
    classify_type,
    detect_credentials,
    generate_report,
    scan_sources,
    trigger_rotation,
)
from .tools import CredentialExposureScannerToolkit


def build_graph(
    toolkit: CredentialExposureScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Credential Exposure Scanner graph.

    Flow:
        scan_sources -> detect_credentials
        -> classify_type -> assess_exposure
        -> trigger_rotation -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_sources(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_credentials(
            _to_dict(state),
            toolkit,
        )

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_type(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_exposure(
            _to_dict(state),
            toolkit,
        )

    async def _rotate(
        state: Any,
    ) -> dict[str, Any]:
        return await trigger_rotation(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(CredentialExposureScannerState)
    graph.add_node("scan_sources", _scan)
    graph.add_node("detect_credentials", _detect)
    graph.add_node("classify_type", _classify)
    graph.add_node("assess_exposure", _assess)
    graph.add_node("trigger_rotation", _rotate)
    graph.add_node("report", _report)

    graph.set_entry_point("scan_sources")
    graph.add_edge(
        "scan_sources",
        "detect_credentials",
    )
    graph.add_edge(
        "detect_credentials",
        "classify_type",
    )
    graph.add_edge(
        "classify_type",
        "assess_exposure",
    )
    graph.add_edge(
        "assess_exposure",
        "trigger_rotation",
    )
    graph.add_edge(
        "trigger_rotation",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_credential_exposure_scanner_graph(
    scan_api: Any | None = None,
    rotation_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Credential Exposure Scanner graph."""
    toolkit = CredentialExposureScannerToolkit(
        scan_api=scan_api,
        rotation_api=rotation_api,
    )
    return build_graph(toolkit)
