"""Threat Landscape Mapper Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_landscape_mapper.models import ThreatLandscapeMapperState
from shieldops.agents.threat_landscape_mapper.tools import ThreatLandscapeMapperToolkit

logger = structlog.get_logger()

_toolkit: ThreatLandscapeMapperToolkit | None = None


def set_toolkit(toolkit: ThreatLandscapeMapperToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatLandscapeMapperToolkit:
    if _toolkit is None:
        return ThreatLandscapeMapperToolkit()
    return _toolkit


async def collect_intel(
    state: ThreatLandscapeMapperState,
) -> dict[str, Any]:
    """Execute collect_intel."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_intel",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_intel done in {dur:.0f}ms",
        ],
    }


async def map_actors(
    state: ThreatLandscapeMapperState,
) -> dict[str, Any]:
    """Execute map_actors."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_actors",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_actors done in {dur:.0f}ms",
        ],
    }


async def identify_trends(
    state: ThreatLandscapeMapperState,
) -> dict[str, Any]:
    """Execute identify_trends."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_trends",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_trends done in {dur:.0f}ms",
        ],
    }


async def assess_relevance(
    state: ThreatLandscapeMapperState,
) -> dict[str, Any]:
    """Execute assess_relevance."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_relevance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_relevance done in {dur:.0f}ms",
        ],
    }


async def prioritize(
    state: ThreatLandscapeMapperState,
) -> dict[str, Any]:
    """Execute prioritize."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "prioritize",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"prioritize done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ThreatLandscapeMapperState,
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
