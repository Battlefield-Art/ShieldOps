"""War Gaming Simulator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.war_gaming_simulator.models import WarGamingSimulatorState
from shieldops.agents.war_gaming_simulator.tools import WarGamingSimulatorToolkit

logger = structlog.get_logger()

_toolkit: WarGamingSimulatorToolkit | None = None


def set_toolkit(toolkit: WarGamingSimulatorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> WarGamingSimulatorToolkit:
    if _toolkit is None:
        return WarGamingSimulatorToolkit()
    return _toolkit


async def design_scenario(
    state: WarGamingSimulatorState,
) -> dict[str, Any]:
    """Execute design_scenario."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "design_scenario",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"design_scenario done in {dur:.0f}ms",
        ],
    }


async def assign_teams(
    state: WarGamingSimulatorState,
) -> dict[str, Any]:
    """Execute assign_teams."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assign_teams",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assign_teams done in {dur:.0f}ms",
        ],
    }


async def execute_rounds(
    state: WarGamingSimulatorState,
) -> dict[str, Any]:
    """Execute execute_rounds."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "execute_rounds",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"execute_rounds done in {dur:.0f}ms",
        ],
    }


async def observe(
    state: WarGamingSimulatorState,
) -> dict[str, Any]:
    """Execute observe."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "observe",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"observe done in {dur:.0f}ms",
        ],
    }


async def score(
    state: WarGamingSimulatorState,
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
    state: WarGamingSimulatorState,
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
