"""Composition root for the evolution subsystem.

Mirrors :mod:`shieldops.licensing.composition` — the same setter/getter
pattern, plus a ``use_test_evolution`` context manager for test seams.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from shieldops.utils.evolution.store import EvolutionStore

__all__ = [
    "get_evolution_store",
    "set_evolution_store",
    "use_test_evolution",
]


_store: EvolutionStore | None = None


def set_evolution_store(store: EvolutionStore | None) -> None:
    """Install (or clear) the process-wide evolution store."""
    global _store
    _store = store


def get_evolution_store() -> EvolutionStore:
    """Return the installed store or raise :class:`RuntimeError`."""
    if _store is None:
        raise RuntimeError(
            "No EvolutionStore installed. Call set_evolution_store(store) "
            "during app startup, or use `use_test_evolution()` in tests."
        )
    return _store


@contextlib.contextmanager
def use_test_evolution(
    store: EvolutionStore | None = None,
) -> Iterator[EvolutionStore]:
    """Swap in an evolution store for the duration of a test block.

    Restores the previous store on exit, **even on exception**.
    """
    previous = _store
    fresh = store or EvolutionStore.in_memory()
    try:
        set_evolution_store(fresh)
        yield fresh
    finally:
        set_evolution_store(previous)
