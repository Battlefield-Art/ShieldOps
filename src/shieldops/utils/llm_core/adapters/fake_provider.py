"""Fake LLM providers — canned responses + scripted failures for tests."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from shieldops.utils.llm_core.types import (
    ModelTier,
    ProviderName,
    ProviderResult,
    TokenUsage,
)


@dataclass
class _Call:
    model: ModelTier
    prompt: str
    response_model_name: str
    tenant_id: str | None
    system_prompt: str | None = None


class FakeLLMProvider:
    """Always-succeeds provider that returns a single canned response.

    Every call is recorded on ``.calls`` in order so tests can assert
    on ``model`` / ``prompt`` / ``tenant_id`` routing.
    """

    name = "fake"

    def __init__(
        self,
        *,
        parsed: Any = None,
        tokens: TokenUsage | None = None,
    ) -> None:
        self._parsed = parsed if parsed is not None else {"ok": True}
        self._tokens = tokens or TokenUsage(
            prompt_tokens=100, completion_tokens=50, total_tokens=150
        )
        self.calls: list[_Call] = []

    async def complete(
        self,
        model: ModelTier,
        prompt: str,
        response_model_name: str,
        *,
        tenant_id: str | None = None,
        system_prompt: str | None = None,
    ) -> ProviderResult:
        self.calls.append(
            _Call(
                model=model,
                prompt=prompt,
                response_model_name=response_model_name,
                tenant_id=tenant_id,
                system_prompt=system_prompt,
            )
        )
        return ProviderResult(
            parsed=self._parsed,
            model_used=model,
            provider_used=ProviderName.FAKE,
            tokens=self._tokens,
            latency_ms=10.0,
        )


@dataclass
class ScriptedLLMProvider:
    """Provider that plays back a scripted sequence of outcomes.

    Each element of ``script`` is either a :class:`ProviderResult`
    (success) or an :class:`Exception` (failure). Tests use this to
    exercise the retry loop — e.g. ``[Exception(), Exception(), result]``
    proves 2 retries lead to success on the third attempt.
    """

    script: Sequence[ProviderResult | Exception]
    name: str = "scripted"
    _cursor: int = field(default=0, init=False)
    calls: list[_Call] = field(default_factory=list, init=False)

    async def complete(
        self,
        model: ModelTier,
        prompt: str,
        response_model_name: str,
        *,
        tenant_id: str | None = None,
        system_prompt: str | None = None,
    ) -> ProviderResult:
        self.calls.append(
            _Call(
                model=model,
                prompt=prompt,
                response_model_name=response_model_name,
                tenant_id=tenant_id,
                system_prompt=system_prompt,
            )
        )
        if self._cursor >= len(self.script):
            raise RuntimeError("scripted provider exhausted")
        item = self.script[self._cursor]
        self._cursor += 1
        if isinstance(item, Exception):
            raise item
        return item
