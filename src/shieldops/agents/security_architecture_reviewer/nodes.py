"""Security Architecture Reviewer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.security_architecture_reviewer.models import SecurityArchitectureReviewerState
from shieldops.agents.security_architecture_reviewer.tools import (
    SecurityArchitectureReviewerToolkit,
)

logger = structlog.get_logger()

_toolkit: SecurityArchitectureReviewerToolkit | None = None


def set_toolkit(toolkit: SecurityArchitectureReviewerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityArchitectureReviewerToolkit:
    if _toolkit is None:
        return SecurityArchitectureReviewerToolkit()
    return _toolkit


async def collect_design(
    state: SecurityArchitectureReviewerState,
) -> dict[str, Any]:
    """Execute collect_design."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_design",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_design done in {dur:.0f}ms",
        ],
    }


async def analyze_components(
    state: SecurityArchitectureReviewerState,
) -> dict[str, Any]:
    """Execute analyze_components."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_components",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_components done in {dur:.0f}ms",
        ],
    }


async def identify_risks(
    state: SecurityArchitectureReviewerState,
) -> dict[str, Any]:
    """Execute identify_risks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_risks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_risks done in {dur:.0f}ms",
        ],
    }


async def evaluate_controls(
    state: SecurityArchitectureReviewerState,
) -> dict[str, Any]:
    """Execute evaluate_controls."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "evaluate_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"evaluate_controls done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: SecurityArchitectureReviewerState,
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
    state: SecurityArchitectureReviewerState,
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
