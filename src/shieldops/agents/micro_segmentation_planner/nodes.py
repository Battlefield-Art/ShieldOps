"""Micro Segmentation Planner Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.micro_segmentation_planner.models import MicroSegmentationPlannerState
from shieldops.agents.micro_segmentation_planner.tools import MicroSegmentationPlannerToolkit

logger = structlog.get_logger()

_toolkit: MicroSegmentationPlannerToolkit | None = None


def set_toolkit(toolkit: MicroSegmentationPlannerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> MicroSegmentationPlannerToolkit:
    if _toolkit is None:
        return MicroSegmentationPlannerToolkit()
    return _toolkit


async def map_traffic(
    state: MicroSegmentationPlannerState,
) -> dict[str, Any]:
    """Execute map_traffic."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_traffic",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_traffic done in {dur:.0f}ms",
        ],
    }


async def identify_segments(
    state: MicroSegmentationPlannerState,
) -> dict[str, Any]:
    """Execute identify_segments."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_segments",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_segments done in {dur:.0f}ms",
        ],
    }


async def define_policies(
    state: MicroSegmentationPlannerState,
) -> dict[str, Any]:
    """Execute define_policies."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "define_policies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"define_policies done in {dur:.0f}ms",
        ],
    }


async def simulate(
    state: MicroSegmentationPlannerState,
) -> dict[str, Any]:
    """Execute simulate."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "simulate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"simulate done in {dur:.0f}ms",
        ],
    }


async def validate(
    state: MicroSegmentationPlannerState,
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
    state: MicroSegmentationPlannerState,
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
