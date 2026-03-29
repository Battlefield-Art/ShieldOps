"""Credential Rotation Manager Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.credential_rotation_manager.models import CredentialRotationManagerState
from shieldops.agents.credential_rotation_manager.tools import CredentialRotationManagerToolkit

logger = structlog.get_logger()

_toolkit: CredentialRotationManagerToolkit | None = None


def set_toolkit(toolkit: CredentialRotationManagerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CredentialRotationManagerToolkit:
    if _toolkit is None:
        return CredentialRotationManagerToolkit()
    return _toolkit


async def discover_credentials(
    state: CredentialRotationManagerState,
) -> dict[str, Any]:
    """Execute discover_credentials."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_credentials",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_credentials done in {dur:.0f}ms",
        ],
    }


async def check_age(
    state: CredentialRotationManagerState,
) -> dict[str, Any]:
    """Execute check_age."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_age",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_age done in {dur:.0f}ms",
        ],
    }


async def schedule_rotation(
    state: CredentialRotationManagerState,
) -> dict[str, Any]:
    """Execute schedule_rotation."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "schedule_rotation",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"schedule_rotation done in {dur:.0f}ms",
        ],
    }


async def execute_rotation(
    state: CredentialRotationManagerState,
) -> dict[str, Any]:
    """Execute execute_rotation."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "execute_rotation",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"execute_rotation done in {dur:.0f}ms",
        ],
    }


async def validate(
    state: CredentialRotationManagerState,
) -> dict[str, Any]:
    """Execute validate."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate done in {dur:.0f}ms",
        ],
    }


async def report(
    state: CredentialRotationManagerState,
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
