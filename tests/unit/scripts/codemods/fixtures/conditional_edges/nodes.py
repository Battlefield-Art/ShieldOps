"""Nodes for the conditional_edges fixture."""

from __future__ import annotations

_TOOLKIT = None


def set_toolkit(tk):
    global _TOOLKIT
    _TOOLKIT = tk


async def detect(state, toolkit=None):
    return state


async def evaluate(state, toolkit=None):
    return state


async def apply_action(state, toolkit=None):
    return state
