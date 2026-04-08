"""Infrastructure Drift Detector — Node implementations."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .tools import InfrastructureDriftDetectorToolkit

logger = structlog.get_logger()

_toolkit: InfrastructureDriftDetectorToolkit | None = None


def _get_toolkit() -> InfrastructureDriftDetectorToolkit:
    if _toolkit is None:
        return InfrastructureDriftDetectorToolkit()
    return _toolkit


async def scan_infrastructure(
    state: Any,
) -> dict[str, Any]:
    """Scan current infrastructure state."""
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
    results = await tk.scan_infrastructure(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "scan_infrastructure",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"scan_infrastructure done in {dur:.0f}ms",
        ],
    }


async def compare_baseline(
    state: Any,
) -> dict[str, Any]:
    """Compare scanned state against baseline."""
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
    results = await tk.compare_baseline(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "compare_baseline",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"compare_baseline done in {dur:.0f}ms",
        ],
    }


async def detect_drift(
    state: Any,
) -> dict[str, Any]:
    """Detect drift between current and baseline."""
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
    results = await tk.detect_drift(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "detect_drift",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"detect_drift done in {dur:.0f}ms",
        ],
    }


async def classify_changes(
    state: Any,
) -> dict[str, Any]:
    """Classify detected changes by drift type."""
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
    results = await tk.classify_changes(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "classify_changes",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"classify_changes done in {dur:.0f}ms",
        ],
    }


async def remediate_drift(
    state: Any,
) -> dict[str, Any]:
    """Remediate detected drift items."""
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
    results = await tk.remediate_drift(tid)
    dur = (time.time() - t0) * 1000
    chain = (
        state.get("reasoning_chain", [])
        if isinstance(state, dict)
        else list(getattr(state, "reasoning_chain", []))
    )
    return {
        "current_step": "remediate_drift",
        "findings": results,
        "reasoning_chain": [
            *chain,
            f"remediate_drift done in {dur:.0f}ms",
        ],
    }


async def report(
    state: Any,
) -> dict[str, Any]:
    """Generate final drift detection report."""
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
