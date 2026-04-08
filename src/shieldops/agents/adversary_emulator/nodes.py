"""Adversary Emulator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.adversary_emulator.models import AdversaryEmulatorState
from shieldops.agents.adversary_emulator.tools import AdversaryEmulatorToolkit

logger = structlog.get_logger()

_toolkit: AdversaryEmulatorToolkit | None = None


def _get_toolkit() -> AdversaryEmulatorToolkit:
    if _toolkit is None:
        return AdversaryEmulatorToolkit()
    return _toolkit


async def select_adversary(
    state: AdversaryEmulatorState,
) -> dict[str, Any]:
    """Execute select_adversary."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "select_adversary",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"select_adversary done in {dur:.0f}ms",
        ],
    }


async def plan_campaign(
    state: AdversaryEmulatorState,
) -> dict[str, Any]:
    """Execute plan_campaign."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "plan_campaign",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"plan_campaign done in {dur:.0f}ms",
        ],
    }


async def execute_ttps(
    state: AdversaryEmulatorState,
) -> dict[str, Any]:
    """Execute execute_ttps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "execute_ttps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"execute_ttps done in {dur:.0f}ms",
        ],
    }


async def observe_defenses(
    state: AdversaryEmulatorState,
) -> dict[str, Any]:
    """Execute observe_defenses."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "observe_defenses",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"observe_defenses done in {dur:.0f}ms",
        ],
    }


async def score(
    state: AdversaryEmulatorState,
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
    state: AdversaryEmulatorState,
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
