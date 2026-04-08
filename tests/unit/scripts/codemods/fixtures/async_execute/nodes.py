"""Nodes for the async_execute fixture."""

from __future__ import annotations

_TOOLKIT = None


def set_toolkit(tk):
    global _TOOLKIT
    _TOOLKIT = tk


async def collect(state, toolkit=None):
    return state


async def summarize(state, toolkit=None):
    return state
