"""Alert Enrichment Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.alert_enrichment_engine.models import AlertEnrichmentEngineState
from shieldops.agents.alert_enrichment_engine.tools import AlertEnrichmentEngineToolkit

logger = structlog.get_logger()

_toolkit: AlertEnrichmentEngineToolkit | None = None


def set_toolkit(toolkit: AlertEnrichmentEngineToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AlertEnrichmentEngineToolkit:
    if _toolkit is None:
        return AlertEnrichmentEngineToolkit()
    return _toolkit


async def ingest_alert(
    state: AlertEnrichmentEngineState,
) -> dict[str, Any]:
    """Execute ingest_alert."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "ingest_alert",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"ingest_alert done in {dur:.0f}ms",
        ],
    }


async def lookup_context(
    state: AlertEnrichmentEngineState,
) -> dict[str, Any]:
    """Execute lookup_context."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "lookup_context",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"lookup_context done in {dur:.0f}ms",
        ],
    }


async def correlate_intel(
    state: AlertEnrichmentEngineState,
) -> dict[str, Any]:
    """Execute correlate_intel."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "correlate_intel",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"correlate_intel done in {dur:.0f}ms",
        ],
    }


async def score_priority(
    state: AlertEnrichmentEngineState,
) -> dict[str, Any]:
    """Execute score_priority."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score_priority",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score_priority done in {dur:.0f}ms",
        ],
    }


async def route(
    state: AlertEnrichmentEngineState,
) -> dict[str, Any]:
    """Execute route."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "route",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"route done in {dur:.0f}ms",
        ],
    }


async def report(
    state: AlertEnrichmentEngineState,
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
