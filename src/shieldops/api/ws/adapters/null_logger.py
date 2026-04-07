"""Null logger — drops everything. Used by contract tests.

Satisfies :class:`shieldops.api.ws.core.ports.Logger`. A
:class:`RecordingLogger` variant is provided for tests that need to
assert on specific log lines (e.g. backpressure warnings).
"""

from __future__ import annotations

from typing import Any


class NullLogger:
    """Logger that does nothing. ``bind`` returns ``self``."""

    def bind(self, **kw: Any) -> NullLogger:
        return self

    def info(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def warning(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def error(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def debug(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass


class RecordingLogger:
    """Test logger that captures every log call.

    Tests can assert against ``logger.records`` — each entry is a
    ``(level, msg, kw)`` tuple.
    """

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []
        self._bound: dict[str, Any] = {}

    def bind(self, **kw: Any) -> RecordingLogger:
        new = RecordingLogger()
        new.records = self.records  # share the record list
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

    def debug(self, msg: str, **kw: Any) -> None:
        self._record("debug", msg, kw)
