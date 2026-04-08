"""AI Bias Scanner Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.ai_bias_scanner.models import AIBiasScannerState
from shieldops.agents.ai_bias_scanner.tools import AIBiasScannerToolkit

logger = structlog.get_logger()

_toolkit: AIBiasScannerToolkit | None = None


def _get_toolkit() -> AIBiasScannerToolkit:
    if _toolkit is None:
        return AIBiasScannerToolkit()
    return _toolkit


async def collect_data(
    state: AIBiasScannerState,
) -> dict[str, Any]:
    """Execute collect_data."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_data done in {duration:.0f}ms",
        ],
    }


async def identify_groups(
    state: AIBiasScannerState,
) -> dict[str, Any]:
    """Execute identify_groups."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "identify_groups",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_groups done in {duration:.0f}ms",
        ],
    }


async def compute_metrics(
    state: AIBiasScannerState,
) -> dict[str, Any]:
    """Execute compute_metrics."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "compute_metrics",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_metrics done in {duration:.0f}ms",
        ],
    }


async def assess_fairness(
    state: AIBiasScannerState,
) -> dict[str, Any]:
    """Execute assess_fairness."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_fairness",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_fairness done in {duration:.0f}ms",
        ],
    }


async def recommend(
    state: AIBiasScannerState,
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
    state: AIBiasScannerState,
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
