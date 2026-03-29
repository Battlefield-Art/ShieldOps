"""model_drift_detector nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.model_drift_detector.models import ModelDriftDetectorState
from shieldops.agents.model_drift_detector.tools import ModelDriftDetectorToolkit

logger = structlog.get_logger()

_toolkit: ModelDriftDetectorToolkit | None = None


def set_toolkit(toolkit: ModelDriftDetectorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ModelDriftDetectorToolkit:
    if _toolkit is None:
        return ModelDriftDetectorToolkit()
    return _toolkit


async def collect(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute collect."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect done in {dur:.0f}ms",
        ],
    }


async def analyze_data_drift(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute analyze_data_drift."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_data_drift",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_data_drift done in {dur:.0f}ms",
        ],
    }


async def analyze_concept_drift(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute analyze_concept_drift."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_concept_drift",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_concept_drift done in {dur:.0f}ms",
        ],
    }


async def analyze_prediction_drift(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute analyze_prediction_drift."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_prediction_drift",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_prediction_drift done in {dur:.0f}ms",
        ],
    }


async def evaluate_thresholds(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute evaluate_thresholds."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "evaluate_thresholds",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"evaluate_thresholds done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ModelDriftDetectorState,
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


async def complete(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute complete."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "complete",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"complete done in {dur:.0f}ms",
        ],
    }


async def failed(
    state: ModelDriftDetectorState,
) -> dict[str, Any]:
    """Execute failed."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "failed",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"failed done in {dur:.0f}ms",
        ],
    }
