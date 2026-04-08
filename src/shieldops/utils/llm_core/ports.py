"""Port Protocols for the LLM orchestrator core.

The orchestrator has zero imports from ``langchain_anthropic``,
``boto3``, ``google.cloud``, ``openai``, ``httpx``, ``redis``,
``structlog``, ``fastapi``. Ruff rule ``SHOP-005`` will enforce this
once it lands.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol, runtime_checkable

from shieldops.utils.llm_core.types import (
    Complexity,
    ContextChunk,
    LLMRequest,
    ModelTier,
    ProviderResult,
    RetryDecision,
)


@runtime_checkable
class LLMProviderPort(Protocol):
    """Calls the actual LLM — Anthropic / Bedrock / Vertex / Azure."""

    name: str

    async def complete(
        self,
        model: ModelTier,
        prompt: str,
        response_model_name: str,
        *,
        tenant_id: str | None = None,
        system_prompt: str | None = None,
    ) -> ProviderResult: ...


@runtime_checkable
class ComplexityClassifierPort(Protocol):
    """Decides which model tier to use for a given prompt."""

    def classify(self, request: LLMRequest) -> Complexity: ...


@runtime_checkable
class ContextRetrieverPort(Protocol):
    """Retrieves runbooks / prior incidents / infrastructure docs."""

    async def retrieve(
        self,
        query: str,
        *,
        tenant_id: str | None = None,
        k: int = 5,
    ) -> list[ContextChunk]: ...


@runtime_checkable
class FitnessRecorderPort(Protocol):
    """Closes the loop to RFC #246's EvolutionStore.

    Every LLM call — success or failure — feeds exactly one record
    through this port. The orchestrator constructs the payload; the
    adapter decides where it goes (default: evolution store; test
    default: an in-memory list).
    """

    async def record_run(
        self,
        *,
        agent_id: str,
        tenant_id: str | None,
        model_used: ModelTier,
        latency_ms: float,
        tokens: int,
        cost_usd: float,
        success: bool,
        forced: bool = False,
    ) -> str: ...


@runtime_checkable
class RetryPolicyPort(Protocol):
    """Decides whether to retry after a failed provider call."""

    def should_retry(self, attempt: int, error: Exception) -> RetryDecision: ...


@runtime_checkable
class Clock(Protocol):
    """Deterministic clock for contract tests."""

    def now(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...


@runtime_checkable
class Logger(Protocol):
    def bind(self, **kw: Any) -> Logger: ...
    def info(self, msg: str, **kw: Any) -> None: ...
    def warning(self, msg: str, **kw: Any) -> None: ...
    def error(self, msg: str, **kw: Any) -> None: ...


# Exported type alias — the classifier → model mapping table lives in
# the orchestrator itself, so plugging in a custom mapping is a
# constructor argument, not a subclass.
ModelFor = Callable[[Complexity], ModelTier]
AsyncModelFor = Callable[[Complexity], Awaitable[ModelTier]]
