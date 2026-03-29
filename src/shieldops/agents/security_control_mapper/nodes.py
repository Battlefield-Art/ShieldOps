"""Security Control Mapper Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.security_control_mapper.models import SecurityControlMapperState
from shieldops.agents.security_control_mapper.tools import SecurityControlMapperToolkit

logger = structlog.get_logger()

_toolkit: SecurityControlMapperToolkit | None = None


def set_toolkit(toolkit: SecurityControlMapperToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityControlMapperToolkit:
    if _toolkit is None:
        return SecurityControlMapperToolkit()
    return _toolkit


async def collect_controls(
    state: SecurityControlMapperState,
) -> dict[str, Any]:
    """Execute collect_controls."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_controls done in {dur:.0f}ms",
        ],
    }


async def map_frameworks(
    state: SecurityControlMapperState,
) -> dict[str, Any]:
    """Execute map_frameworks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_frameworks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_frameworks done in {dur:.0f}ms",
        ],
    }


async def identify_gaps(
    state: SecurityControlMapperState,
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


async def cross_reference(
    state: SecurityControlMapperState,
) -> dict[str, Any]:
    """Execute cross_reference."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "cross_reference",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"cross_reference done in {dur:.0f}ms",
        ],
    }


async def score(
    state: SecurityControlMapperState,
) -> dict[str, Any]:
    """Execute score."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score done in {dur:.0f}ms",
        ],
    }


async def report(
    state: SecurityControlMapperState,
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
