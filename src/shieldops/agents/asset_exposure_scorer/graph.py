"""Asset Exposure Scorer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: AssetExposureScorerToolkit):  # type: ignore[no-untyped-def]
    """Build the asset_exposure_scorer agent graph (linear sequence)."""
    return build_linear_graph(
        AssetExposureScorerState,
        [
            ("discover_assets", discover_assets),
            ("fingerprint_services", fingerprint_services),
            ("check_vulns", check_vulns),
            ("score_exposure", score_exposure),
            ("track_changes", track_changes),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
