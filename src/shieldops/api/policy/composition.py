"""Composition root for the request-policy engine.

Same pattern as :mod:`shieldops.licensing.composition` and
:mod:`shieldops.utils.evolution.composition` — a global setter behind
a :func:`get` that raises if nothing is installed, plus a
``use_test_policy_engine`` context manager for test seams, plus a
``build_in_memory_engine`` factory that assembles a fully-defaulted
engine with all in-memory adapters.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from shieldops.api.policy.adapters import (
    CapturingEventLog,
    InMemoryBucketStore,
    ManualClock,
    NullMetricsSink,
    StaticPlanLoader,
)
from shieldops.api.policy.deps import PolicyDeps
from shieldops.api.policy.engine import RequestPolicyEngine
from shieldops.api.policy.types import Plan

__all__ = [
    "build_in_memory_engine",
    "get_policy_engine",
    "set_policy_engine",
    "use_test_policy_engine",
]


_engine: RequestPolicyEngine | None = None


def set_policy_engine(engine: RequestPolicyEngine | None) -> None:
    """Install (or clear) the process-wide policy engine."""
    global _engine
    _engine = engine


def get_policy_engine() -> RequestPolicyEngine:
    """Return the installed engine or raise :class:`RuntimeError`."""
    if _engine is None:
        raise RuntimeError(
            "No RequestPolicyEngine installed. Call set_policy_engine(engine) "
            "during app startup, or use `use_test_policy_engine()` in tests."
        )
    return _engine


def build_in_memory_engine(
    *,
    default_plan: Plan | None = None,
    start_ts: float = 0.0,
) -> tuple[RequestPolicyEngine, PolicyDeps]:
    """Build a fully-defaulted engine with all in-memory adapters.

    Returns both the engine and the deps so tests can poke at the
    specific adapters (``deps.plans.set_usage(...)``, ``deps.clock.advance(...)``,
    etc.).
    """
    deps = PolicyDeps(
        buckets=InMemoryBucketStore(),
        plans=StaticPlanLoader(default=default_plan),
        clock=ManualClock(start=start_ts),
        metrics=NullMetricsSink(),
        events=CapturingEventLog(),
    )
    return RequestPolicyEngine(deps), deps


@contextlib.contextmanager
def use_test_policy_engine(
    engine: RequestPolicyEngine | None = None,
) -> Iterator[RequestPolicyEngine]:
    """Swap in a test engine for the duration of a block.

    Restores the previous engine on exit, including exception paths.
    """
    previous = _engine
    fresh = engine or build_in_memory_engine()[0]
    try:
        set_policy_engine(fresh)
        yield fresh
    finally:
        set_policy_engine(previous)
