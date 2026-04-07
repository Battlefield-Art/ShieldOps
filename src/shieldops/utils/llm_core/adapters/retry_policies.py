"""Retry policy adapters — ``NoRetry`` for deterministic tests and
``ScriptedRetry`` for exercising the retry loop."""

from __future__ import annotations

from collections.abc import Sequence

from shieldops.utils.llm_core.types import RetryDecision, Stop


class NoRetry:
    """Always stop immediately. The default for contract tests that
    want to assert on single-attempt behavior."""

    def should_retry(
        self,
        attempt: int,
        error: Exception,  # noqa: ARG002
    ) -> RetryDecision:
        return Stop()


class ScriptedRetry:
    """Walk a pre-defined list of decisions.

    Usage::

        retry = ScriptedRetry([Sleep(0.0), Sleep(0.0), Stop()])
        # First two errors → retry with 0s sleep.
        # Third error → stop.
    """

    def __init__(self, script: Sequence[RetryDecision]) -> None:
        self._script = list(script)
        self._cursor = 0

    def should_retry(
        self,
        attempt: int,
        error: Exception,  # noqa: ARG002
    ) -> RetryDecision:
        if self._cursor >= len(self._script):
            return Stop()
        decision = self._script[self._cursor]
        self._cursor += 1
        return decision
