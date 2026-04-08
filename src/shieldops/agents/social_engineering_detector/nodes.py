"""Social Engineering Detector Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.social_engineering_detector.models import SocialEngineeringDetectorState
from shieldops.agents.social_engineering_detector.tools import SocialEngineeringDetectorToolkit

logger = structlog.get_logger()

_toolkit: SocialEngineeringDetectorToolkit | None = None


def _get_toolkit() -> SocialEngineeringDetectorToolkit:
    if _toolkit is None:
        return SocialEngineeringDetectorToolkit()
    return _toolkit


async def collect_signals(
    state: SocialEngineeringDetectorState,
) -> dict[str, Any]:
    """Execute collect_signals."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_signals",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_signals done in {duration:.0f}ms",
        ],
    }


async def analyze_patterns(
    state: SocialEngineeringDetectorState,
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
    state: SocialEngineeringDetectorState,
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


async def assess_risk(
    state: SocialEngineeringDetectorState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {duration:.0f}ms",
        ],
    }


async def recommend(
    state: SocialEngineeringDetectorState,
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
    state: SocialEngineeringDetectorState,
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
