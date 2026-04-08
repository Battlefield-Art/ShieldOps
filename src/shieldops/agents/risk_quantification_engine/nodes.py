"""Node implementations for the Risk Quantification Engine."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.risk_quantification_engine.tools import (
    RiskQuantificationEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: RiskQuantificationEngineToolkit | None = None


def _get_toolkit() -> RiskQuantificationEngineToolkit:
    if _toolkit is None:
        return RiskQuantificationEngineToolkit()
    return _toolkit


async def identify_assets(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Identify and value organizational assets."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.identify_assets(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_assets",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"identify_assets done in {dur:.0f}ms",
        ],
    }


async def model_threats(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Model threats against identified assets."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.model_threats(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "model_threats",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"model_threats done in {dur:.0f}ms",
        ],
    }


async def calculate_exposure(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Calculate risk exposure for each asset."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.calculate_exposure(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "calculate_exposure",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"calculate_exposure done in {dur:.0f}ms",
        ],
    }


async def estimate_loss(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Estimate potential financial losses."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.estimate_loss(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "estimate_loss",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"estimate_loss done in {dur:.0f}ms",
        ],
    }


async def prioritize_risks(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Prioritize risks by impact and likelihood."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.prioritize_risks(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "prioritize_risks",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"prioritize_risks done in {dur:.0f}ms",
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate risk quantification report."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.report(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"report done in {dur:.0f}ms",
        ],
    }
