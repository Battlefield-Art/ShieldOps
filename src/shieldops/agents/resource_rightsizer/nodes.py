"""Resource Rightsizer — Node implementations."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .tools import ResourceRightsizerToolkit

logger = structlog.get_logger()

_toolkit: ResourceRightsizerToolkit | None = None


def _get_toolkit() -> ResourceRightsizerToolkit:
    if _toolkit is None:
        return ResourceRightsizerToolkit()
    return _toolkit


async def collect_utilization(
    state: Any,
) -> dict[str, Any]:
    """Collect resource utilization metrics."""
    t0 = time.time()
    tk = _get_toolkit()
    tid = (
        state.get("tenant_id", "")
        if isinstance(
            state,
            dict,
        )
        else getattr(state, "tenant_id", "")
    )
    results = await tk.collect_utilization(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "collect_utilization",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"collect_utilization done in {dur:.0f}ms",
        ],
    }


async def analyze_patterns(
    state: Any,
) -> dict[str, Any]:
    """Analyze utilization patterns."""
    t0 = time.time()
    tk = _get_toolkit()
    tid = (
        state.get("tenant_id", "")
        if isinstance(
            state,
            dict,
        )
        else getattr(state, "tenant_id", "")
    )
    results = await tk.analyze_patterns(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "analyze_patterns",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"analyze_patterns done in {dur:.0f}ms",
        ],
    }


async def identify_overprovisioned(
    state: Any,
) -> dict[str, Any]:
    """Identify overprovisioned resources."""
    t0 = time.time()
    tk = _get_toolkit()
    tid = (
        state.get("tenant_id", "")
        if isinstance(
            state,
            dict,
        )
        else getattr(state, "tenant_id", "")
    )
    results = await tk.identify_overprovisioned(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "identify_overprovisioned",
        "findings": results,
        "reasoning_chain": [
            *chain,
            (f"identify_overprovisioned done in {dur:.0f}ms"),
        ],
    }


async def recommend_sizes(
    state: Any,
) -> dict[str, Any]:
    """Recommend optimal resource sizes."""
    t0 = time.time()
    tk = _get_toolkit()
    tid = (
        state.get("tenant_id", "")
        if isinstance(
            state,
            dict,
        )
        else getattr(state, "tenant_id", "")
    )
    results = await tk.recommend_sizes(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "recommend_sizes",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"recommend_sizes done in {dur:.0f}ms",
        ],
    }


async def validate_impact(
    state: Any,
) -> dict[str, Any]:
    """Validate performance impact of changes."""
    t0 = time.time()
    tk = _get_toolkit()
    tid = (
        state.get("tenant_id", "")
        if isinstance(
            state,
            dict,
        )
        else getattr(state, "tenant_id", "")
    )
    results = await tk.validate_impact(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "validate_impact",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"validate_impact done in {dur:.0f}ms",
        ],
    }


async def report(
    state: Any,
) -> dict[str, Any]:
    """Generate final rightsizing report."""
    t0 = time.time()
    tk = _get_toolkit()
    tid = (
        state.get("tenant_id", "")
        if isinstance(
            state,
            dict,
        )
        else getattr(state, "tenant_id", "")
    )
    results = await tk.generate_report(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "report",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"report done in {dur:.0f}ms",
        ],
    }
