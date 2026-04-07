"""Composition root for the LLM orchestrator.

Mirrors the pattern used by RFCs #242, #243, #244, #245, #246:
global setter behind a getter that raises if nothing is installed,
``use_test_llm_orchestrator`` context manager for test seams,
``build_in_memory_orchestrator`` factory that assembles a fully
defaulted orchestrator with all in-memory adapters.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from shieldops.utils.llm_core.adapters import (
    FakeLLMProvider,
    FixedClassifier,
    InMemoryFitnessRecorder,
    ManualClock,
    NoRetry,
    NullContextRetriever,
    NullLogger,
)
from shieldops.utils.llm_core.deps import LLMDeps
from shieldops.utils.llm_core.orchestrator import LLMOrchestrator
from shieldops.utils.llm_core.types import Complexity

__all__ = [
    "build_in_memory_orchestrator",
    "get_llm_orchestrator",
    "set_llm_orchestrator",
    "use_test_llm_orchestrator",
]


_orchestrator: LLMOrchestrator | None = None


def set_llm_orchestrator(orchestrator: LLMOrchestrator | None) -> None:
    global _orchestrator
    _orchestrator = orchestrator


def get_llm_orchestrator() -> LLMOrchestrator:
    if _orchestrator is None:
        raise RuntimeError(
            "No LLMOrchestrator installed. Call set_llm_orchestrator(orch) "
            "during app startup, or use `use_test_llm_orchestrator()` in tests."
        )
    return _orchestrator


def build_in_memory_orchestrator(
    *,
    complexity: Complexity = Complexity.MEDIUM,
) -> tuple[LLMOrchestrator, LLMDeps]:
    """Factory that assembles a fully-defaulted in-memory orchestrator."""
    deps = LLMDeps(
        provider=FakeLLMProvider(),
        classifier=FixedClassifier(complexity),
        context=NullContextRetriever(),
        fitness=InMemoryFitnessRecorder(),
        retry=NoRetry(),
        clock=ManualClock(),
        log=NullLogger(),
    )
    return LLMOrchestrator(deps), deps


@contextlib.contextmanager
def use_test_llm_orchestrator(
    orchestrator: LLMOrchestrator | None = None,
) -> Iterator[LLMOrchestrator]:
    previous = _orchestrator
    fresh = orchestrator or build_in_memory_orchestrator()[0]
    try:
        set_llm_orchestrator(fresh)
        yield fresh
    finally:
        set_llm_orchestrator(previous)
