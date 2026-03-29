"""Threat Surface Minimizer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_surface_minimizer.models import ThreatSurfaceMinimizerState
from shieldops.agents.threat_surface_minimizer.tools import ThreatSurfaceMinimizerToolkit

logger = structlog.get_logger()

_toolkit: ThreatSurfaceMinimizerToolkit | None = None


def set_toolkit(toolkit: ThreatSurfaceMinimizerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatSurfaceMinimizerToolkit:
    if _toolkit is None:
        return ThreatSurfaceMinimizerToolkit()
    return _toolkit


async def discover_surface(
    state: ThreatSurfaceMinimizerState,
) -> dict[str, Any]:
    """Execute discover_surface."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_surface",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_surface done in {dur:.0f}ms",
        ],
    }


async def map_exposure(
    state: ThreatSurfaceMinimizerState,
) -> dict[str, Any]:
    """Execute map_exposure."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_exposure",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_exposure done in {dur:.0f}ms",
        ],
    }


async def prioritize_risks(
    state: ThreatSurfaceMinimizerState,
) -> dict[str, Any]:
    """Execute prioritize_risks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "prioritize_risks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"prioritize_risks done in {dur:.0f}ms",
        ],
    }


async def recommend_reduction(
    state: ThreatSurfaceMinimizerState,
) -> dict[str, Any]:
    """Execute recommend_reduction."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend_reduction",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend_reduction done in {dur:.0f}ms",
        ],
    }


async def validate(
    state: ThreatSurfaceMinimizerState,
) -> dict[str, Any]:
    """Execute validate."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ThreatSurfaceMinimizerState,
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
