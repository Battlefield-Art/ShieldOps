"""Environmental Monitor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.environmental_monitor.models import EnvironmentalMonitorState
from shieldops.agents.environmental_monitor.tools import EnvironmentalMonitorToolkit

logger = structlog.get_logger()

_toolkit: EnvironmentalMonitorToolkit | None = None


def _get_toolkit() -> EnvironmentalMonitorToolkit:
    if _toolkit is None:
        return EnvironmentalMonitorToolkit()
    return _toolkit


async def collect_readings(
    state: EnvironmentalMonitorState,
) -> dict[str, Any]:
    """Execute collect_readings."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_readings",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_readings done in {duration:.0f}ms",
        ],
    }


async def check_thresholds(
    state: EnvironmentalMonitorState,
) -> dict[str, Any]:
    """Execute check_thresholds."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "check_thresholds",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_thresholds done in {duration:.0f}ms",
        ],
    }


async def correlate_events(
    state: EnvironmentalMonitorState,
) -> dict[str, Any]:
    """Execute correlate_events."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "correlate_events",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"correlate_events done in {duration:.0f}ms",
        ],
    }


async def assess_risk(
    state: EnvironmentalMonitorState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {duration:.0f}ms",
        ],
    }


async def alert(
    state: EnvironmentalMonitorState,
) -> dict[str, Any]:
    """Execute alert."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "alert",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"alert done in {duration:.0f}ms",
        ],
    }


async def report(
    state: EnvironmentalMonitorState,
) -> dict[str, Any]:
    """Execute report."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report done in {duration:.0f}ms",
        ],
    }
