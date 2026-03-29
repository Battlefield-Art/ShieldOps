"""Playbook Optimizer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.playbook_optimizer.models import PlaybookOptimizerState
from shieldops.agents.playbook_optimizer.tools import PlaybookOptimizerToolkit

logger = structlog.get_logger()

_toolkit: PlaybookOptimizerToolkit | None = None


def set_toolkit(toolkit: PlaybookOptimizerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PlaybookOptimizerToolkit:
    if _toolkit is None:
        return PlaybookOptimizerToolkit()
    return _toolkit


async def analyze_executions(
    state: PlaybookOptimizerState,
) -> dict[str, Any]:
    """Execute analyze_executions."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_executions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_executions done in {dur:.0f}ms",
        ],
    }


async def identify_bottlenecks(
    state: PlaybookOptimizerState,
) -> dict[str, Any]:
    """Execute identify_bottlenecks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_bottlenecks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_bottlenecks done in {dur:.0f}ms",
        ],
    }


async def suggest_improvements(
    state: PlaybookOptimizerState,
) -> dict[str, Any]:
    """Execute suggest_improvements."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "suggest_improvements",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"suggest_improvements done in {dur:.0f}ms",
        ],
    }


async def simulate(
    state: PlaybookOptimizerState,
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
    state: PlaybookOptimizerState,
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
    state: PlaybookOptimizerState,
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
