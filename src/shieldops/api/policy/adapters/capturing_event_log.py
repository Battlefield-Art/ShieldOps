"""Capturing event log — records every emitted event for test assertions."""

from __future__ import annotations

from typing import Any


class CapturingEventLog:
    """Records every ``emit`` call.

    ``.events`` is a list of ``(name, fields)`` tuples in call order.
    """

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def emit(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))

    def count_where(self, event: str, **match: Any) -> int:
        return sum(
            1 for n, f in self.events if n == event and all(f.get(k) == v for k, v in match.items())
        )
