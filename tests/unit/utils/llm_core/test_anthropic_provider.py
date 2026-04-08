"""Contract tests for :class:`AnthropicProviderAdapter` — RFC #248 PR-3.

See ghantakiran/ShieldOps#290. These tests lock the adapter's contract
with the orchestrator without actually hitting the Anthropic API. We
stub out langchain's ``ChatAnthropic`` entirely: the adapter itself
builds the client via :meth:`AnthropicProviderAdapter._client_for`, and
the tests monkeypatch that hook to return a fake that records calls
and returns canned ``{"raw", "parsed"}`` dicts — the shape langchain
returns when ``with_structured_output(..., include_raw=True)`` is used.

The adapter already lives behind a port, so every test constructs the
adapter directly and asserts on the :class:`ProviderResult` it emits.

Five contract tests:

1. ``name`` is the ``ProviderName.ANTHROPIC`` string. Composition roots
   and logs identify the adapter by ``.name``.
2. ``complete`` returns the parsed Pydantic model the registry resolved.
3. ``complete`` records token usage from ``usage_metadata``.
4. ``complete`` picks the right concrete Claude model string per tier
   so the cost-optimized router (Haiku/Sonnet/Opus) is load-bearing.
5. ``complete`` raises ``KeyError`` on an unknown ``response_model_name``
   so callers get a clean failure at registry-lookup time instead of
   a confusing langchain validation error downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import BaseModel

from shieldops.utils.llm_core.adapters.anthropic_provider import (
    DEFAULT_TIER_MODELS,
    AnthropicProviderAdapter,
)
from shieldops.utils.llm_core.types import ModelTier, ProviderName


class Verdict(BaseModel):
    """Canned response schema used by the tests."""

    label: str
    score: float


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class _FakeAIMessage:
    content: str = "ok"
    usage_metadata: dict[str, int] | None = None


@dataclass
class _FakeStructuredRunnable:
    parsed: Any
    raw: _FakeAIMessage
    calls: list[list[Any]] = field(default_factory=list)

    async def ainvoke(self, messages: list[Any]) -> dict[str, Any]:
        self.calls.append(messages)
        return {"parsed": self.parsed, "raw": self.raw, "parsing_error": None}


@dataclass
class _FakeChatAnthropic:
    """Stand-in for :class:`langchain_anthropic.ChatAnthropic`."""

    model: str
    parsed: Any
    raw: _FakeAIMessage
    structured: _FakeStructuredRunnable | None = None

    def with_structured_output(self, schema: Any, include_raw: bool = False) -> Any:
        self.structured = _FakeStructuredRunnable(parsed=self.parsed, raw=self.raw)
        # Track the schema so tests can assert on it if they want.
        self.structured.schema = schema  # type: ignore[attr-defined]
        return self.structured


def _install_fake_clients(
    adapter: AnthropicProviderAdapter,
    *,
    parsed: Any,
    usage: dict[str, int] | None = None,
) -> dict[ModelTier, _FakeChatAnthropic]:
    """Pre-seed the adapter's client cache with fakes for every tier."""
    raw = _FakeAIMessage(usage_metadata=usage)
    fakes: dict[ModelTier, _FakeChatAnthropic] = {}
    for tier in ModelTier:
        fake = _FakeChatAnthropic(
            model=DEFAULT_TIER_MODELS[tier],
            parsed=parsed,
            raw=raw,
        )
        fakes[tier] = fake
        adapter._clients[tier] = fake  # type: ignore[assignment]
    return fakes


def _make_adapter() -> AnthropicProviderAdapter:
    return AnthropicProviderAdapter(
        api_key="sk-test-not-a-real-key",
        response_models={"Verdict": Verdict},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_adapter_name_is_anthropic() -> None:
    adapter = _make_adapter()
    assert adapter.name == ProviderName.ANTHROPIC.value == "anthropic"


@pytest.mark.asyncio
async def test_complete_returns_parsed_pydantic_model() -> None:
    adapter = _make_adapter()
    verdict = Verdict(label="malicious", score=0.92)
    _install_fake_clients(adapter, parsed=verdict)

    result = await adapter.complete(
        ModelTier.SONNET,
        prompt="Classify this alert.",
        response_model_name="Verdict",
    )

    assert isinstance(result.parsed, Verdict)
    assert result.parsed.label == "malicious"
    assert result.parsed.score == pytest.approx(0.92)
    assert result.provider_used is ProviderName.ANTHROPIC
    assert result.model_used is ModelTier.SONNET
    assert result.latency_ms >= 0.0


@pytest.mark.asyncio
async def test_complete_records_token_usage() -> None:
    adapter = _make_adapter()
    usage = {"input_tokens": 123, "output_tokens": 45, "total_tokens": 168}
    _install_fake_clients(
        adapter,
        parsed=Verdict(label="clean", score=0.1),
        usage=usage,
    )

    result = await adapter.complete(
        ModelTier.HAIKU,
        prompt="noop",
        response_model_name="Verdict",
    )

    assert result.tokens.prompt_tokens == 123
    assert result.tokens.completion_tokens == 45
    assert result.tokens.total_tokens == 168


@pytest.mark.asyncio
async def test_complete_picks_correct_model_for_tier() -> None:
    adapter = _make_adapter()
    fakes = _install_fake_clients(
        adapter,
        parsed=Verdict(label="ok", score=0.5),
    )

    await adapter.complete(
        ModelTier.OPUS,
        prompt="deep analysis",
        response_model_name="Verdict",
    )

    # Only the Opus client should have been driven.
    assert fakes[ModelTier.OPUS].structured is not None
    assert fakes[ModelTier.HAIKU].structured is None
    assert fakes[ModelTier.SONNET].structured is None
    assert fakes[ModelTier.OPUS].model == DEFAULT_TIER_MODELS[ModelTier.OPUS]

    # And the schema the adapter handed langchain is the one from the
    # registry — not some arbitrary BaseModel.
    assert fakes[ModelTier.OPUS].structured.schema is Verdict  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_complete_raises_on_unknown_response_model_name() -> None:
    adapter = _make_adapter()
    _install_fake_clients(adapter, parsed=Verdict(label="x", score=0.0))

    with pytest.raises(KeyError, match="Unknown response_model_name"):
        await adapter.complete(
            ModelTier.SONNET,
            prompt="irrelevant",
            response_model_name="NotInRegistry",
        )
