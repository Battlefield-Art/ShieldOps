"""Data Lineage Tracker Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.data_lineage_tracker.models import DataLineageTrackerState
from shieldops.agents.data_lineage_tracker.tools import DataLineageTrackerToolkit

logger = structlog.get_logger()

_toolkit: DataLineageTrackerToolkit | None = None


def set_toolkit(toolkit: DataLineageTrackerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> DataLineageTrackerToolkit:
    if _toolkit is None:
        return DataLineageTrackerToolkit()
    return _toolkit


async def discover_sources(
    state: DataLineageTrackerState,
) -> dict[str, Any]:
    """Execute discover_sources."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_sources",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_sources done in {dur:.0f}ms",
        ],
    }


async def map_transformations(
    state: DataLineageTrackerState,
) -> dict[str, Any]:
    """Execute map_transformations."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_transformations",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_transformations done in {dur:.0f}ms",
        ],
    }


async def trace_lineage(
    state: DataLineageTrackerState,
) -> dict[str, Any]:
    """Execute trace_lineage."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "trace_lineage",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"trace_lineage done in {dur:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: DataLineageTrackerState,
) -> dict[str, Any]:
    """Execute detect_anomalies."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_anomalies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_anomalies done in {dur:.0f}ms",
        ],
    }


async def validate(
    state: DataLineageTrackerState,
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
    state: DataLineageTrackerState,
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
