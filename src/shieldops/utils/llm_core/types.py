"""Public types for the LLM orchestrator.

All types here are pure data. The orchestrator core reads and writes
them; adapters translate them at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Model tiers + providers
# ---------------------------------------------------------------------------


class ModelTier(StrEnum):
    """Cost/capability tiers exposed by the router.

    The mapping from tier → concrete vendor model lives in the
    ``model_for: Callable[[Complexity], ModelTier]`` argument of
    :class:`LLMOrchestrator` (default: :data:`DEFAULT_MODEL_TABLE`).
    """

    HAIKU = "haiku"
    SONNET = "sonnet"
    OPUS = "opus"


class ProviderName(StrEnum):
    """Which cloud provider actually served the request."""

    ANTHROPIC = "anthropic"
    BEDROCK = "bedrock"
    VERTEX = "vertex"
    AZURE = "azure"
    FAKE = "fake"  # for tests


class Complexity(StrEnum):
    """What the classifier decided about a prompt."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Request / response
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LLMRequest:
    """Everything the orchestrator needs to make a call.

    The 1,851 existing ``llm_structured`` call sites become a shim
    that builds this request from its positional args + optional
    keyword-only hints.
    """

    prompt: str
    response_model_name: str
    """String name of the Pydantic model to parse into. Kept as a
    string rather than ``type[BaseModel]`` in PR-1 so the orchestrator
    core doesn't need to import pydantic — adapters handle validation."""
    agent_id: str
    tenant_id: str | None = None
    hint_complexity: Complexity | None = None
    context_query: str | None = None
    fallback: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenUsage:
    """Prompt/completion/total token counts from the provider."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class ContextChunk:
    """One piece of retrieved context to enrich the prompt."""

    source: str
    content: str
    score: float = 0.0


@dataclass(frozen=True)
class ProviderResult:
    """What a provider adapter returns to the orchestrator."""

    parsed: Any
    model_used: ModelTier
    provider_used: ProviderName
    tokens: TokenUsage
    latency_ms: float


@dataclass(frozen=True)
class LLMResponse:
    """What the orchestrator returns to callers (via the shim)."""

    parsed: Any
    model_used: ModelTier
    provider_used: ProviderName
    complexity: Complexity
    tokens: TokenUsage
    latency_ms: float
    attempts: int
    context_chunks: int
    used_fallback: bool
    fitness_run_id: str | None


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryDecision:
    """Base — callers use :class:`Stop` or :class:`Sleep`."""


@dataclass(frozen=True)
class Stop(RetryDecision):
    """Give up — no more retries."""


@dataclass(frozen=True)
class Sleep(RetryDecision):
    """Sleep this many seconds and retry."""

    seconds: float


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LLMUnavailable(Exception):
    """All retries exhausted and no fallback was provided."""


class LLMValidationError(Exception):
    """The provider returned a response that could not be parsed into
    the requested schema."""
