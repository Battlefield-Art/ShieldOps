"""Incident Similarity Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.incident_similarity_engine.models import IncidentSimilarityEngineState
from shieldops.agents.incident_similarity_engine.tools import IncidentSimilarityEngineToolkit

logger = structlog.get_logger()

_toolkit: IncidentSimilarityEngineToolkit | None = None


def set_toolkit(toolkit: IncidentSimilarityEngineToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentSimilarityEngineToolkit:
    if _toolkit is None:
        return IncidentSimilarityEngineToolkit()
    return _toolkit


async def ingest_incident(
    state: IncidentSimilarityEngineState,
) -> dict[str, Any]:
    """Execute ingest_incident."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "ingest_incident",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"ingest_incident done in {dur:.0f}ms",
        ],
    }


async def extract_features(
    state: IncidentSimilarityEngineState,
) -> dict[str, Any]:
    """Execute extract_features."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "extract_features",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"extract_features done in {dur:.0f}ms",
        ],
    }


async def compute_similarity(
    state: IncidentSimilarityEngineState,
) -> dict[str, Any]:
    """Execute compute_similarity."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "compute_similarity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_similarity done in {dur:.0f}ms",
        ],
    }


async def rank_matches(
    state: IncidentSimilarityEngineState,
) -> dict[str, Any]:
    """Execute rank_matches."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "rank_matches",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"rank_matches done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: IncidentSimilarityEngineState,
) -> dict[str, Any]:
    """Execute recommend."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend done in {dur:.0f}ms",
        ],
    }


async def report(
    state: IncidentSimilarityEngineState,
) -> dict[str, Any]:
    """Execute report."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report done in {dur:.0f}ms",
        ],
    }
