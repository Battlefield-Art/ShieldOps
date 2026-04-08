"""Hunt Hypothesis Generator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.hunt_hypothesis_generator.models import HuntHypothesisGeneratorState
from shieldops.agents.hunt_hypothesis_generator.tools import HuntHypothesisGeneratorToolkit

logger = structlog.get_logger()

_toolkit: HuntHypothesisGeneratorToolkit | None = None


def _get_toolkit() -> HuntHypothesisGeneratorToolkit:
    if _toolkit is None:
        return HuntHypothesisGeneratorToolkit()
    return _toolkit


async def analyze_intel(
    state: HuntHypothesisGeneratorState,
) -> dict[str, Any]:
    """Execute analyze_intel."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_intel",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_intel done in {dur:.0f}ms",
        ],
    }


async def identify_gaps(
    state: HuntHypothesisGeneratorState,
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


async def generate_hypotheses(
    state: HuntHypothesisGeneratorState,
) -> dict[str, Any]:
    """Execute generate_hypotheses."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_hypotheses",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_hypotheses done in {dur:.0f}ms",
        ],
    }


async def prioritize(
    state: HuntHypothesisGeneratorState,
) -> dict[str, Any]:
    """Execute prioritize."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "prioritize",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"prioritize done in {dur:.0f}ms",
        ],
    }


async def create_queries(
    state: HuntHypothesisGeneratorState,
) -> dict[str, Any]:
    """Execute create_queries."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "create_queries",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"create_queries done in {dur:.0f}ms",
        ],
    }


async def report(
    state: HuntHypothesisGeneratorState,
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
