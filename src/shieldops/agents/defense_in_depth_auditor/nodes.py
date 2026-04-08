"""Defense In Depth Auditor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.defense_in_depth_auditor.models import DefenseInDepthAuditorState
from shieldops.agents.defense_in_depth_auditor.tools import DefenseInDepthAuditorToolkit

logger = structlog.get_logger()

_toolkit: DefenseInDepthAuditorToolkit | None = None


def _get_toolkit() -> DefenseInDepthAuditorToolkit:
    if _toolkit is None:
        return DefenseInDepthAuditorToolkit()
    return _toolkit


async def map_layers(
    state: DefenseInDepthAuditorState,
) -> dict[str, Any]:
    """Execute map_layers."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_layers",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_layers done in {dur:.0f}ms",
        ],
    }


async def assess_controls(
    state: DefenseInDepthAuditorState,
) -> dict[str, Any]:
    """Execute assess_controls."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_controls done in {dur:.0f}ms",
        ],
    }


async def identify_gaps(
    state: DefenseInDepthAuditorState,
) -> dict[str, Any]:
    """Execute identify_gaps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_gaps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_gaps done in {dur:.0f}ms",
        ],
    }


async def test_resilience(
    state: DefenseInDepthAuditorState,
) -> dict[str, Any]:
    """Execute test_resilience."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "test_resilience",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"test_resilience done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: DefenseInDepthAuditorState,
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
    state: DefenseInDepthAuditorState,
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
