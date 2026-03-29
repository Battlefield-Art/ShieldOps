"""CCTV Analytics Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.cctv_analytics.models import CCTVAnalyticsState
from shieldops.agents.cctv_analytics.tools import CCTVAnalyticsToolkit

logger = structlog.get_logger()

_toolkit: CCTVAnalyticsToolkit | None = None


def set_toolkit(toolkit: CCTVAnalyticsToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CCTVAnalyticsToolkit:
    if _toolkit is None:
        return CCTVAnalyticsToolkit()
    return _toolkit


async def collect_feeds(
    state: CCTVAnalyticsState,
) -> dict[str, Any]:
    """Execute collect_feeds."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_feeds",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_feeds done in {duration:.0f}ms",
        ],
    }


async def detect_motion(
    state: CCTVAnalyticsState,
) -> dict[str, Any]:
    """Execute detect_motion."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "detect_motion",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_motion done in {duration:.0f}ms",
        ],
    }


async def analyze_behavior(
    state: CCTVAnalyticsState,
) -> dict[str, Any]:
    """Execute analyze_behavior."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "analyze_behavior",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_behavior done in {duration:.0f}ms",
        ],
    }


async def classify_events(
    state: CCTVAnalyticsState,
) -> dict[str, Any]:
    """Execute classify_events."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "classify_events",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_events done in {duration:.0f}ms",
        ],
    }


async def alert(
    state: CCTVAnalyticsState,
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
    state: CCTVAnalyticsState,
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
