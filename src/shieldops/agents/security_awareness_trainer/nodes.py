"""Node implementations for the Security Awareness Trainer."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.security_awareness_trainer.tools import (
    SecurityAwarenessTrainerToolkit,
)

logger = structlog.get_logger()

_toolkit: SecurityAwarenessTrainerToolkit | None = None


def set_toolkit(
    toolkit: SecurityAwarenessTrainerToolkit,
) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SecurityAwarenessTrainerToolkit:
    if _toolkit is None:
        return SecurityAwarenessTrainerToolkit()
    return _toolkit


async def assess_baseline(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assess employee baseline security competency."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.assess_baseline(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_baseline",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"assess_baseline done in {dur:.0f}ms",
        ],
    }


async def design_campaign(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Design targeted training campaign."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.design_campaign(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "design_campaign",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"design_campaign done in {dur:.0f}ms",
        ],
    }


async def generate_content(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate training content and materials."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.generate_content(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_content",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"generate_content done in {dur:.0f}ms",
        ],
    }


async def deliver_training(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Deliver training to target audiences."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.deliver_training(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "deliver_training",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"deliver_training done in {dur:.0f}ms",
        ],
    }


async def measure_effectiveness(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Measure training effectiveness and impact."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.measure_effectiveness(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "measure_effectiveness",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"measure_effectiveness done in {dur:.0f}ms",
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate training effectiveness report."""
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
