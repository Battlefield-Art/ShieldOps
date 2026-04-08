"""Weird-shape runner: no Runner class, no async run method — should be skipped."""

from __future__ import annotations


def some_helper():
    return 42


class HelperThing:
    """Not a *Runner suffix."""

    def synchronous_method(self) -> None:
        pass
