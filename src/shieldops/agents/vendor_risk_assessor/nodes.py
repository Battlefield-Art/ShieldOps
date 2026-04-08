"""Vendor Risk Assessor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.vendor_risk_assessor.models import VendorRiskAssessorState
from shieldops.agents.vendor_risk_assessor.tools import VendorRiskAssessorToolkit

logger = structlog.get_logger()

_toolkit: VendorRiskAssessorToolkit | None = None


def _get_toolkit() -> VendorRiskAssessorToolkit:
    if _toolkit is None:
        return VendorRiskAssessorToolkit()
    return _toolkit


async def collect_data(
    state: VendorRiskAssessorState,
) -> dict[str, Any]:
    """Execute collect_data."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_data done in {dur:.0f}ms",
        ],
    }


async def score_risk(
    state: VendorRiskAssessorState,
) -> dict[str, Any]:
    """Execute score_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score_risk done in {dur:.0f}ms",
        ],
    }


async def evaluate_controls(
    state: VendorRiskAssessorState,
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


async def classify_vendor(
    state: VendorRiskAssessorState,
) -> dict[str, Any]:
    """Execute classify_vendor."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_vendor",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_vendor done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: VendorRiskAssessorState,
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
    state: VendorRiskAssessorState,
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
