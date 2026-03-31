"""Asset Exposure Scorer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AssetExposureScorerState
from .nodes import (
    check_vulns,
    discover_assets,
    fingerprint_services,
    generate_report,
    score_exposure,
    track_changes,
)
from .tools import AssetExposureScorerToolkit


def build_graph(
    toolkit: AssetExposureScorerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Asset Exposure Scorer graph.

    Flow:
        discover_assets -> fingerprint_services
        -> check_vulns -> score_exposure
        -> track_changes -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_assets(
            _to_dict(state),
            toolkit,
        )

    async def _fingerprint(
        state: Any,
    ) -> dict[str, Any]:
        return await fingerprint_services(
            _to_dict(state),
            toolkit,
        )

    async def _vulns(
        state: Any,
    ) -> dict[str, Any]:
        return await check_vulns(
            _to_dict(state),
            toolkit,
        )

    async def _score(
        state: Any,
    ) -> dict[str, Any]:
        return await score_exposure(
            _to_dict(state),
            toolkit,
        )

    async def _track(
        state: Any,
    ) -> dict[str, Any]:
        return await track_changes(
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

    graph = StateGraph(AssetExposureScorerState)
    graph.add_node("discover_assets", _discover)
    graph.add_node("fingerprint_services", _fingerprint)
    graph.add_node("check_vulns", _vulns)
    graph.add_node("score_exposure", _score)
    graph.add_node("track_changes", _track)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_assets")
    graph.add_edge(
        "discover_assets",
        "fingerprint_services",
    )
    graph.add_edge(
        "fingerprint_services",
        "check_vulns",
    )
    graph.add_edge(
        "check_vulns",
        "score_exposure",
    )
    graph.add_edge(
        "score_exposure",
        "track_changes",
    )
    graph.add_edge(
        "track_changes",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_asset_exposure_scorer_graph(
    scanner_api: Any | None = None,
    vuln_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Asset Exposure Scorer graph."""
    toolkit = AssetExposureScorerToolkit(
        scanner_api=scanner_api,
        vuln_db=vuln_db,
    )
    return build_graph(toolkit)
