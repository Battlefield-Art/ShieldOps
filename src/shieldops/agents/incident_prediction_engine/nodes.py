"""Incident Prediction Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.incident_prediction_engine.models import IncidentPredictionEngineState
from shieldops.agents.incident_prediction_engine.tools import IncidentPredictionEngineToolkit

logger = structlog.get_logger()

_toolkit: IncidentPredictionEngineToolkit | None = None


def _get_toolkit() -> IncidentPredictionEngineToolkit:
    if _toolkit is None:
        return IncidentPredictionEngineToolkit()
    return _toolkit


async def collect_signals(
    state: IncidentPredictionEngineState,
) -> dict[str, Any]:
    """Execute collect_signals."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_signals",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_signals done in {dur:.0f}ms",
        ],
    }


async def extract_features(
    state: IncidentPredictionEngineState,
) -> dict[str, Any]:
    """Execute extract_features."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "extract_features",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"extract_features done in {dur:.0f}ms",
        ],
    }


async def run_models(
    state: IncidentPredictionEngineState,
) -> dict[str, Any]:
    """Execute run_models."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "run_models",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"run_models done in {dur:.0f}ms",
        ],
    }


async def rank_predictions(
    state: IncidentPredictionEngineState,
) -> dict[str, Any]:
    """Execute rank_predictions."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "rank_predictions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"rank_predictions done in {dur:.0f}ms",
        ],
    }


async def alert(
    state: IncidentPredictionEngineState,
) -> dict[str, Any]:
    """Execute alert."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "alert",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"alert done in {dur:.0f}ms",
        ],
    }


async def report(
    state: IncidentPredictionEngineState,
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
