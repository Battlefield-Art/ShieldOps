"""Null + capturing metrics sinks.

:class:`NullMetricsSink` drops every call — used by contract tests that
don't assert on metrics.

:class:`CapturingMetricsSink` records every call — used by contract
tests that assert on metric emission (e.g. "a rate-limited request
emits ``policy.rate_limited``").
"""

from __future__ import annotations


class NullMetricsSink:
    """Drops every metric call."""

    def incr(self, name: str, **labels: str) -> None:  # noqa: D401
        pass

    def observe(self, name: str, value: float, **labels: str) -> None:  # noqa: D401
        pass


class CapturingMetricsSink:
    """Records every metric call for test assertions.

    ``.counters`` is a list of ``(name, labels)`` tuples in call order.
    ``.observations`` is a list of ``(name, value, labels)`` tuples.
    """

    def __init__(self) -> None:
        self.counters: list[tuple[str, dict[str, str]]] = []
        self.observations: list[tuple[str, float, dict[str, str]]] = []

    def incr(self, name: str, **labels: str) -> None:
        self.counters.append((name, labels))

    def observe(self, name: str, value: float, **labels: str) -> None:
        self.observations.append((name, value, labels))

    def count_where(self, name: str, **labels: str) -> int:
        """Return the number of ``incr`` calls matching ``name`` and the
        given labels (subset match)."""
        return sum(
            1
            for n, lbls in self.counters
            if n == name and all(lbls.get(k) == v for k, v in labels.items())
        )
