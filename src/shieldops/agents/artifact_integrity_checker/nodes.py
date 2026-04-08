"""Artifact Integrity Checker Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.artifact_integrity_checker.models import ArtifactIntegrityCheckerState
from shieldops.agents.artifact_integrity_checker.tools import ArtifactIntegrityCheckerToolkit

logger = structlog.get_logger()

_toolkit: ArtifactIntegrityCheckerToolkit | None = None


def _get_toolkit() -> ArtifactIntegrityCheckerToolkit:
    if _toolkit is None:
        return ArtifactIntegrityCheckerToolkit()
    return _toolkit


async def collect_artifacts(
    state: ArtifactIntegrityCheckerState,
) -> dict[str, Any]:
    """Execute collect_artifacts."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_artifacts",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_artifacts done in {dur:.0f}ms",
        ],
    }


async def verify_signatures(
    state: ArtifactIntegrityCheckerState,
) -> dict[str, Any]:
    """Execute verify_signatures."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "verify_signatures",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"verify_signatures done in {dur:.0f}ms",
        ],
    }


async def check_checksums(
    state: ArtifactIntegrityCheckerState,
) -> dict[str, Any]:
    """Execute check_checksums."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_checksums",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_checksums done in {dur:.0f}ms",
        ],
    }


async def validate_provenance(
    state: ArtifactIntegrityCheckerState,
) -> dict[str, Any]:
    """Execute validate_provenance."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_provenance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_provenance done in {dur:.0f}ms",
        ],
    }


async def assess(
    state: ArtifactIntegrityCheckerState,
) -> dict[str, Any]:
    """Execute assess."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ArtifactIntegrityCheckerState,
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
