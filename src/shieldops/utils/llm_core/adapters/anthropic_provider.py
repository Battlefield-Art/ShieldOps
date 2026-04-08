"""Production ``LLMProviderPort`` adapter for Anthropic Claude.

RFC #248 PR-3 — see ghantakiran/ShieldOps#290.

Wraps :class:`langchain_anthropic.ChatAnthropic` so the
:class:`shieldops.utils.llm_core.orchestrator.LLMOrchestrator` can talk
to Claude in production. The adapter is ports-first: it imports only
from ``langchain_anthropic`` / ``langchain_core`` / ``pydantic`` /
``structlog`` plus the local ``llm_core`` types — zero dependency on
``shieldops.connectors``, ``shieldops.api``, or ``shieldops.db``.

The legacy singleton at ``shieldops.utils.llm`` (wired into 1,851 call
sites) keeps working unchanged. PR-4 (#291) will switch those call
sites over to the orchestrator + this adapter; this PR only adds the
adapter and its contract tests.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from shieldops.utils.llm_core.types import (
    ModelTier,
    ProviderName,
    ProviderResult,
    TokenUsage,
)

logger = structlog.get_logger(__name__)

# Concrete vendor model string per tier. Kept aligned with the legacy
# ``shieldops.utils.llm_router`` mapping so PR-4's cutover is a no-op
# for existing callers.
DEFAULT_TIER_MODELS: dict[ModelTier, str] = {
    ModelTier.HAIKU: "claude-haiku-4-20250514",
    ModelTier.SONNET: "claude-sonnet-4-20250514",
    ModelTier.OPUS: "claude-opus-4-20250514",
}


class AnthropicProviderAdapter:
    """Production :class:`LLMProviderPort` that calls Claude via langchain.

    One :class:`ChatAnthropic` instance is created per :class:`ModelTier`
    on first use and cached for the adapter's lifetime — cross-tier
    routing doesn't re-instantiate the HTTP client on every call.

    Parameters
    ----------
    api_key:
        Anthropic API key. Passed straight to ``ChatAnthropic``.
    response_models:
        Registry mapping a response-model *name* (the string the
        orchestrator carries on :class:`LLMRequest`) to the concrete
        pydantic ``BaseModel`` subclass the adapter should parse into.
        The adapter does not import agent schemas itself — callers
        assemble the registry at composition time.
    default_model:
        Fallback Claude model string if a tier is missing from
        ``tier_models``. Defaults to Sonnet 4, matching legacy
        ``shieldops.utils.llm.get_llm``.
    max_tokens / temperature:
        Match legacy ``shieldops.utils.llm.get_llm`` defaults exactly.
    tier_models:
        Override the tier → concrete-model mapping. Defaults to
        :data:`DEFAULT_TIER_MODELS`.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        response_models: dict[str, type[BaseModel]],
        default_model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        temperature: float = 0.1,
        tier_models: dict[ModelTier, str] | None = None,
    ) -> None:
        self._api_key = api_key
        self._response_models = dict(response_models)
        self._default_model = default_model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._tier_models = dict(tier_models) if tier_models else dict(DEFAULT_TIER_MODELS)
        self._clients: dict[ModelTier, ChatAnthropic] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def complete(
        self,
        model: ModelTier,
        prompt: str,
        response_model_name: str,
        *,
        tenant_id: str | None = None,
        system_prompt: str | None = None,
    ) -> ProviderResult:
        schema = self._resolve_schema(response_model_name)
        llm = self._client_for(model)
        structured = llm.with_structured_output(schema, include_raw=True)

        system_content = (
            system_prompt
            if system_prompt is not None
            else "You are ShieldOps, an AI security analyst."
        )
        messages = [
            SystemMessage(content=system_content),
            HumanMessage(content=prompt),
        ]

        started = time.perf_counter()
        try:
            raw = await structured.ainvoke(messages)
        except Exception as exc:  # noqa: BLE001 — re-raised with context
            logger.warning(
                "anthropic_provider_failed",
                model=self._tier_models.get(model, self._default_model),
                tenant_id=tenant_id,
                error=str(exc),
            )
            raise
        latency_ms = (time.perf_counter() - started) * 1000.0

        parsed, tokens = _unpack_structured_response(raw)

        logger.debug(
            "anthropic_provider_complete",
            model=self._tier_models.get(model, self._default_model),
            tenant_id=tenant_id,
            tokens_total=tokens.total_tokens,
            latency_ms=latency_ms,
        )

        return ProviderResult(
            parsed=parsed,
            model_used=model,
            provider_used=ProviderName.ANTHROPIC,
            tokens=tokens,
            latency_ms=latency_ms,
        )

    def register_schema(self, name: str, cls: type[BaseModel]) -> None:
        """Register a Pydantic response model by string name at runtime.

        Added in RFC #248 PR-4 so the legacy
        ``shieldops.utils.llm.llm_structured`` shim can delegate
        ad-hoc schemas into the orchestrator without requiring the
        composition root to pre-enumerate every agent's response
        model. Idempotent — re-registering the same name with the
        same class is a no-op; re-registering with a *different*
        class raises to catch name collisions.
        """
        existing = self._response_models.get(name)
        if existing is cls:
            return
        if existing is not None and existing is not cls:
            raise ValueError(
                f"AnthropicProviderAdapter.register_schema: collision on name={name!r}: "
                f"existing={existing!r} new={cls!r}"
            )
        self._response_models[name] = cls

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_schema(self, response_model_name: str) -> type[BaseModel]:
        try:
            return self._response_models[response_model_name]
        except KeyError as exc:
            known = sorted(self._response_models)
            raise KeyError(
                f"Unknown response_model_name={response_model_name!r}; registry has {known}"
            ) from exc

    def _client_for(self, tier: ModelTier) -> ChatAnthropic:
        cached = self._clients.get(tier)
        if cached is not None:
            return cached
        model_id = self._tier_models.get(tier, self._default_model)
        client = ChatAnthropic(  # type: ignore[call-arg]
            model=model_id,
            api_key=self._api_key,  # type: ignore[arg-type]
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        self._clients[tier] = client
        return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unpack_structured_response(raw: Any) -> tuple[Any, TokenUsage]:
    """Extract parsed payload + token usage from a langchain response.

    ``with_structured_output(schema, include_raw=True)`` returns a dict
    shaped like ``{"raw": AIMessage, "parsed": BaseModel | dict,
    "parsing_error": Exception | None}``. We tolerate the legacy shape
    (a bare parsed object) as a fallback so the adapter survives
    langchain minor-version drift.
    """
    parsed: Any
    raw_msg: Any = None
    if isinstance(raw, dict) and "parsed" in raw:
        parsed = raw.get("parsed")
        raw_msg = raw.get("raw")
    else:
        parsed = raw

    tokens = _extract_token_usage(raw_msg)
    return parsed, tokens


def _extract_token_usage(raw_msg: Any) -> TokenUsage:
    if raw_msg is None:
        return TokenUsage()
    usage = getattr(raw_msg, "usage_metadata", None)
    if not usage:
        return TokenUsage()
    # usage_metadata may be a dict or a pydantic model, depending on
    # langchain-core version.
    if isinstance(usage, dict):
        prompt = int(usage.get("input_tokens", 0) or 0)
        completion = int(usage.get("output_tokens", 0) or 0)
        total = int(usage.get("total_tokens", prompt + completion) or (prompt + completion))
    else:
        prompt = int(getattr(usage, "input_tokens", 0) or 0)
        completion = int(getattr(usage, "output_tokens", 0) or 0)
        total = int(getattr(usage, "total_tokens", prompt + completion) or (prompt + completion))
    return TokenUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
    )
