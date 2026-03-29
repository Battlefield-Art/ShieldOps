"""NIST Framework Mapper Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.nist_framework_mapper.models import NISTFrameworkMapperState
from shieldops.agents.nist_framework_mapper.tools import NISTFrameworkMapperToolkit

logger = structlog.get_logger()

_toolkit: NISTFrameworkMapperToolkit | None = None


def set_toolkit(toolkit: NISTFrameworkMapperToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> NISTFrameworkMapperToolkit:
    if _toolkit is None:
        return NISTFrameworkMapperToolkit()
    return _toolkit


async def map_functions(
    state: NISTFrameworkMapperState,
) -> dict[str, Any]:
    """Execute map_functions."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "map_functions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_functions done in {duration:.0f}ms",
        ],
    }


async def assess_categories(
    state: NISTFrameworkMapperState,
) -> dict[str, Any]:
    """Execute assess_categories."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_categories",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_categories done in {duration:.0f}ms",
        ],
    }


async def score_maturity(
    state: NISTFrameworkMapperState,
) -> dict[str, Any]:
    """Execute score_maturity."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "score_maturity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score_maturity done in {duration:.0f}ms",
        ],
    }


async def identify_gaps(
    state: NISTFrameworkMapperState,
) -> dict[str, Any]:
    """Execute identify_gaps."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "identify_gaps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_gaps done in {duration:.0f}ms",
        ],
    }


async def recommend(
    state: NISTFrameworkMapperState,
) -> dict[str, Any]:
    """Execute recommend."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "recommend",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend done in {duration:.0f}ms",
        ],
    }


async def report(
    state: NISTFrameworkMapperState,
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
