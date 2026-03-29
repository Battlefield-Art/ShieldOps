"""SLA Breach Predictor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.sla_breach_predictor.models import SlaBreachPredictorState
from shieldops.agents.sla_breach_predictor.tools import SlaBreachPredictorToolkit

logger = structlog.get_logger()

_toolkit: SlaBreachPredictorToolkit | None = None


def set_toolkit(toolkit: SlaBreachPredictorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SlaBreachPredictorToolkit:
    if _toolkit is None:
        return SlaBreachPredictorToolkit()
    return _toolkit


async def collect_tickets(
    state: SlaBreachPredictorState,
) -> dict[str, Any]:
    """Execute collect_tickets."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_tickets",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_tickets done in {dur:.0f}ms",
        ],
    }


async def compute_velocity(
    state: SlaBreachPredictorState,
) -> dict[str, Any]:
    """Execute compute_velocity."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "compute_velocity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_velocity done in {dur:.0f}ms",
        ],
    }


async def predict_breach(
    state: SlaBreachPredictorState,
) -> dict[str, Any]:
    """Execute predict_breach."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "predict_breach",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"predict_breach done in {dur:.0f}ms",
        ],
    }


async def rank_risk(
    state: SlaBreachPredictorState,
) -> dict[str, Any]:
    """Execute rank_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "rank_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"rank_risk done in {dur:.0f}ms",
        ],
    }


async def alert(
    state: SlaBreachPredictorState,
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
    state: SlaBreachPredictorState,
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
