"""Node functions for the canonical_run fixture."""

from __future__ import annotations

_TOOLKIT = None


def set_toolkit(tk):
    global _TOOLKIT
    _TOOLKIT = tk


async def triage(state, toolkit=None):
    return state


async def investigate(state, toolkit=None):
    return state


async def finalize(state, toolkit=None):
    return state
