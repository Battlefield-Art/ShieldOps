"""Node implementations for the IOC Enrichment Engine Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.ioc_enrichment_engine.tools import (
    IOCEnrichmentEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: IOCEnrichmentEngineToolkit | None = None


def _get_toolkit() -> IOCEnrichmentEngineToolkit:
    if _toolkit is None:
        return IOCEnrichmentEngineToolkit()
    return _toolkit


async def collect_iocs(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Collect IOCs from configured sources."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.collect_iocs(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_iocs",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"collect_iocs done in {dur:.0f}ms",
        ],
    }


async def query_sources(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Query enrichment sources for IOC context."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.query_sources(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "query_sources",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"query_sources done in {dur:.0f}ms",
        ],
    }


async def correlate_context(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Correlate IOC context across sources."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.correlate_context(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "correlate_context",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"correlate_context done in {dur:.0f}ms",
        ],
    }


async def assess_risk(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assess risk level for enriched IOCs."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.assess_risk(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"assess_risk done in {dur:.0f}ms",
        ],
    }


async def tag_indicators(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Tag indicators with actionable metadata."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.tag_indicators(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "tag_indicators",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"tag_indicators done in {dur:.0f}ms",
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate final enrichment report."""
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
