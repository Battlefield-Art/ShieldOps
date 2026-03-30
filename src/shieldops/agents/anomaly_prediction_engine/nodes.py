"""Anomaly Prediction Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.anomaly_prediction_engine.models import (
    AnomalyPredictionEngineState,
)
from shieldops.agents.anomaly_prediction_engine.tools import (
    AnomalyPredictionEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: AnomalyPredictionEngineToolkit | None = None


def set_toolkit(
    toolkit: AnomalyPredictionEngineToolkit,
) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AnomalyPredictionEngineToolkit:
    if _toolkit is None:
        return AnomalyPredictionEngineToolkit()
    return _toolkit


async def ingest_metrics(
    state: AnomalyPredictionEngineState,
) -> dict[str, Any]:
    """Ingest time-series metrics."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.ingest_metrics()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "ingest_metrics",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"ingest_metrics done in {dur:.0f}ms",
        ],
    }


async def train_models(
    state: AnomalyPredictionEngineState,
) -> dict[str, Any]:
    """Train prediction models."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.train_models()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "train_models",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"train_models done in {dur:.0f}ms",
        ],
    }


async def generate_predictions(
    state: AnomalyPredictionEngineState,
) -> dict[str, Any]:
    """Generate anomaly predictions."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.generate_predictions()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_predictions",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_predictions done in {dur:.0f}ms",
        ],
    }


async def validate_accuracy(
    state: AnomalyPredictionEngineState,
) -> dict[str, Any]:
    """Validate prediction accuracy."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.validate_accuracy()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_accuracy",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_accuracy done in {dur:.0f}ms",
        ],
    }


async def publish_alerts(
    state: AnomalyPredictionEngineState,
) -> dict[str, Any]:
    """Publish predictive alerts."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.publish_alerts()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "publish_alerts",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"publish_alerts done in {dur:.0f}ms",
        ],
    }


async def report(
    state: AnomalyPredictionEngineState,
) -> dict[str, Any]:
    """Generate final report."""
    return {
        "current_step": "report",
        "stats": {
            "total_findings": len(state.findings),
            "steps": len(state.reasoning_chain),
        },
        "reasoning_chain": [
            *state.reasoning_chain,
            "report generated",
        ],
    }
