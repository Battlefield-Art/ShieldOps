"""Inference Attack Detector Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.inference_attack_detector.models import InferenceAttackDetectorState
from shieldops.agents.inference_attack_detector.tools import InferenceAttackDetectorToolkit

logger = structlog.get_logger()

_toolkit: InferenceAttackDetectorToolkit | None = None


def _get_toolkit() -> InferenceAttackDetectorToolkit:
    if _toolkit is None:
        return InferenceAttackDetectorToolkit()
    return _toolkit


async def collect_queries(
    state: InferenceAttackDetectorState,
) -> dict[str, Any]:
    """Execute collect_queries."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_queries",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_queries done in {duration:.0f}ms",
        ],
    }


async def analyze_patterns(
    state: InferenceAttackDetectorState,
) -> dict[str, Any]:
    """Execute analyze_patterns."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "analyze_patterns",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_patterns done in {duration:.0f}ms",
        ],
    }


async def classify_attack(
    state: InferenceAttackDetectorState,
) -> dict[str, Any]:
    """Execute classify_attack."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "classify_attack",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_attack done in {duration:.0f}ms",
        ],
    }


async def assess_impact(
    state: InferenceAttackDetectorState,
) -> dict[str, Any]:
    """Execute assess_impact."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_impact",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_impact done in {duration:.0f}ms",
        ],
    }


async def mitigate(
    state: InferenceAttackDetectorState,
) -> dict[str, Any]:
    """Execute mitigate."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "mitigate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"mitigate done in {duration:.0f}ms",
        ],
    }


async def report(
    state: InferenceAttackDetectorState,
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
