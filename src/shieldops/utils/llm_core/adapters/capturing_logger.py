"""Capturing logger for LLM contract tests that assert on log output."""

from __future__ import annotations

from typing import Any


class CapturingLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []
        self._bound: dict[str, Any] = {}

    def bind(self, **kw: Any) -> CapturingLogger:
        new = CapturingLogger()
        new.records = self.records
        new._bound = {**self._bound, **kw}
        return new

    def _record(self, level: str, msg: str, kw: dict[str, Any]) -> None:
        self.records.append((level, msg, {**self._bound, **kw}))

    def info(self, msg: str, **kw: Any) -> None:
        self._record("info", msg, kw)

    def warning(self, msg: str, **kw: Any) -> None:
        self._record("warning", msg, kw)

    def error(self, msg: str, **kw: Any) -> None:
        self._record("error", msg, kw)

    def count_where(self, level: str, msg: str) -> int:
        return sum(1 for lvl, m, _ in self.records if lvl == level and m == msg)
