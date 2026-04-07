"""Composition root for the AgentRuntime.

Mirrors the pattern used by RFCs #242, #243, #244, #245, #246, #248:
global setter behind a getter that raises if nothing is installed,
``use_test_agent_runtime`` context manager for test seams,
``build_in_memory_runtime`` factory that assembles a fully-defaulted
runtime with all in-memory adapters.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from shieldops.agents.runtime.adapters import (
    AllowAllPolicy,
    CapturingAuditLog,
    CapturingHub,
    InMemoryConnectorRouter,
    InMemoryEvolutionRecorder,
    InMemoryLicenseManager,
    InMemoryPersistence,
    ManualClock,
    NullAgentLogger,
)
from shieldops.agents.runtime.runtime import AgentRuntime

__all__ = [
    "build_in_memory_runtime",
    "get_agent_runtime",
    "set_agent_runtime",
    "use_test_agent_runtime",
]


_runtime: AgentRuntime | None = None


def set_agent_runtime(runtime: AgentRuntime | None) -> None:
    global _runtime
    _runtime = runtime


def get_agent_runtime() -> AgentRuntime:
    if _runtime is None:
        raise RuntimeError(
            "No AgentRuntime installed. Call set_agent_runtime(runtime) "
            "during app startup, or use `use_test_agent_runtime()` in tests."
        )
    return _runtime


def build_in_memory_runtime() -> AgentRuntime:
    """Assemble a fully-defaulted in-memory AgentRuntime for tests.

    All 9 ports wired with capturing / allow-all adapters so tests can
    construct one in a single line and drive the full lifecycle."""
    return AgentRuntime(
        connectors=InMemoryConnectorRouter(),
        policy=AllowAllPolicy(),
        hub=CapturingHub(),
        evolution=InMemoryEvolutionRecorder(),
        license=InMemoryLicenseManager(),
        persist=InMemoryPersistence(),
        audit=CapturingAuditLog(),
        clock=ManualClock(),
        log=NullAgentLogger(),
    )


@contextlib.contextmanager
def use_test_agent_runtime(
    runtime: AgentRuntime | None = None,
) -> Iterator[AgentRuntime]:
    previous = _runtime
    fresh = runtime or build_in_memory_runtime()
    try:
        set_agent_runtime(fresh)
        yield fresh
    finally:
        set_agent_runtime(previous)
