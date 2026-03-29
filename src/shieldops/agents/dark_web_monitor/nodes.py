"""Dark Web Monitor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.dark_web_monitor.models import DarkWebMonitorState
from shieldops.agents.dark_web_monitor.tools import DarkWebMonitorToolkit

logger = structlog.get_logger()

_toolkit: DarkWebMonitorToolkit | None = None


def set_toolkit(toolkit: DarkWebMonitorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> DarkWebMonitorToolkit:
    if _toolkit is None:
        return DarkWebMonitorToolkit()
    return _toolkit


async def crawl_sources(
    state: DarkWebMonitorState,
) -> dict[str, Any]:
    """Execute crawl_sources."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "crawl_sources",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"crawl_sources done in {dur:.0f}ms",
        ],
    }


async def extract_mentions(
    state: DarkWebMonitorState,
) -> dict[str, Any]:
    """Execute extract_mentions."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "extract_mentions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"extract_mentions done in {dur:.0f}ms",
        ],
    }


async def match_assets(
    state: DarkWebMonitorState,
) -> dict[str, Any]:
    """Execute match_assets."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "match_assets",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"match_assets done in {dur:.0f}ms",
        ],
    }


async def assess_risk(
    state: DarkWebMonitorState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {dur:.0f}ms",
        ],
    }


async def alert(
    state: DarkWebMonitorState,
) -> dict[str, Any]:
    """Execute alert."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "alert",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"alert done in {dur:.0f}ms",
        ],
    }


async def report(
    state: DarkWebMonitorState,
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
