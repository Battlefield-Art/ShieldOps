"""Typed TokenUsage model with per-model cost calculation (#7).

Replaces the free-form ``AgentRun.token_usage: dict`` blob with a proper
Pydantic model. Metrics dashboards can rely on a stable shape and the
``estimated_cost_usd`` field without re-parsing vendor-specific JSON.

Pricing is hard-coded per model in ``_PRICING`` and expressed as USD per
million tokens. Unknown models return a cost of 0.0 (explicit zero rather
than raise — metrics should still render for unpriced experiments).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

# USD per million tokens — (input, output)
_PRICING: dict[str, tuple[float, float]] = {
    # Claude 4.x family
    "claude-opus-4-6": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    # Legacy Claude 3.x fallbacks
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-opus": (15.0, 75.0),
    "claude-3-haiku": (0.25, 1.25),
    # OpenAI
    "gpt-4o": (5.0, 15.0),
    "gpt-4o-mini": (0.15, 0.6),
}


class TokenUsage(BaseModel):
    """Per-run LLM token accounting with cost estimation."""

    model: str = ""
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0.0, ge=0)

    @model_validator(mode="after")
    def _fill_derived_fields(self) -> TokenUsage:
        # If no total provided, compute it
        if self.total_tokens == 0 and (self.prompt_tokens + self.completion_tokens) > 0:
            object.__setattr__(self, "total_tokens", self.prompt_tokens + self.completion_tokens)
        # If no cost provided, compute it from pricing table
        if self.estimated_cost_usd == 0.0:
            pricing = _PRICING.get(self.model)
            if pricing is not None:
                input_rate, output_rate = pricing
                cost = (self.prompt_tokens / 1_000_000) * input_rate + (
                    self.completion_tokens / 1_000_000
                ) * output_rate
                object.__setattr__(self, "estimated_cost_usd", round(cost, 6))
        return self

    @classmethod
    def from_raw(cls, raw: dict[str, Any] | None) -> TokenUsage:
        """Build from a legacy free-form ``token_usage`` dict with missing keys."""
        if not raw:
            return cls()
        return cls(
            model=raw.get("model", "") or "",
            prompt_tokens=int(raw.get("prompt_tokens") or 0),
            completion_tokens=int(raw.get("completion_tokens") or 0),
            total_tokens=int(raw.get("total_tokens") or 0),
            estimated_cost_usd=float(raw.get("estimated_cost_usd") or 0.0),
        )
