"""Node implementations for the Threat Feed Aggregator Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_feed_aggregator.tools import (
    ThreatFeedAggregatorToolkit,
)

logger = structlog.get_logger()

_toolkit: ThreatFeedAggregatorToolkit | None = None


def set_toolkit(
    toolkit: ThreatFeedAggregatorToolkit,
) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ThreatFeedAggregatorToolkit:
    if _toolkit is None:
        return ThreatFeedAggregatorToolkit()
    return _toolkit


async def discover_feeds(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Discover available threat intelligence feeds."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.discover_feeds(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_feeds",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"discover_feeds done in {dur:.0f}ms",
        ],
    }


async def ingest_indicators(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Ingest indicators from discovered feeds."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.ingest_indicators(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "ingest_indicators",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"ingest_indicators done in {dur:.0f}ms",
        ],
    }


async def normalize_data(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Normalize ingested data to standard format."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.normalize_data(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "normalize_data",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"normalize_data done in {dur:.0f}ms",
        ],
    }


async def deduplicate(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Deduplicate normalized indicators."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.deduplicate(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "deduplicate",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"deduplicate done in {dur:.0f}ms",
        ],
    }


async def score_relevance(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Score relevance of deduplicated indicators."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.score_relevance(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score_relevance",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"score_relevance done in {dur:.0f}ms",
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate final aggregation report."""
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
