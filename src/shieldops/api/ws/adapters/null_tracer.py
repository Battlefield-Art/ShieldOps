"""Null tracer — no-op spans. Used by contract tests.

Satisfies :class:`shieldops.api.ws.core.ports.Tracer`. Production
will use an OpenTelemetry-backed adapter in PR-2.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any


class _NullSpan(AbstractContextManager[Any]):
    def __enter__(self) -> _NullSpan:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class NullTracer:
    def span(self, name: str, **attrs: Any) -> AbstractContextManager[Any]:
        return _NullSpan()
