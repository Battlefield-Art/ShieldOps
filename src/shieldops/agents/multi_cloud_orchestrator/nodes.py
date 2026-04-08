"""Multi Cloud Orchestrator — Node implementations."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .tools import MultiCloudOrchestratorToolkit

logger = structlog.get_logger()

_toolkit: MultiCloudOrchestratorToolkit | None = None


def _get_toolkit() -> MultiCloudOrchestratorToolkit:
    if _toolkit is None:
        return MultiCloudOrchestratorToolkit()
    return _toolkit


async def discover_resources(
    state: Any,
) -> dict[str, Any]:
    """Discover resources across all clouds."""
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
    results = await tk.discover_resources(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "discover_resources",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"discover_resources done in {dur:.0f}ms",
        ],
    }


async def normalize_inventory(
    state: Any,
) -> dict[str, Any]:
    """Normalize inventory across providers."""
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
    results = await tk.normalize_inventory(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "normalize_inventory",
        "findings": results,
        "reasoning_chain": [
            *chain,
            (f"normalize_inventory done in {dur:.0f}ms"),
        ],
    }


async def compare_pricing(
    state: Any,
) -> dict[str, Any]:
    """Compare pricing across cloud providers."""
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
    results = await tk.compare_pricing(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "compare_pricing",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"compare_pricing done in {dur:.0f}ms",
        ],
    }


async def optimize_placement(
    state: Any,
) -> dict[str, Any]:
    """Optimize resource placement strategy."""
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
    results = await tk.optimize_placement(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "optimize_placement",
        "findings": results,
        "reasoning_chain": [
            *chain,
            (f"optimize_placement done in {dur:.0f}ms"),
        ],
    }


async def execute_migration(
    state: Any,
) -> dict[str, Any]:
    """Execute cross-cloud migration plan."""
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
    results = await tk.execute_migration(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "execute_migration",
        "findings": results,
        "reasoning_chain": [
            *chain,
            (f"execute_migration done in {dur:.0f}ms"),
        ],
    }


async def report(
    state: Any,
) -> dict[str, Any]:
    """Generate final orchestration report."""
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
