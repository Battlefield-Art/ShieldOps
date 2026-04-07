"""Null + capturing loggers for LLM orchestrator tests."""

from __future__ import annotations

from typing import Any


class NullLogger:
    def bind(self, **kw: Any) -> NullLogger:  # noqa: D401
        return self

    def info(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def warning(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def error(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass
