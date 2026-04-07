"""LLMOrchestrator — unified LLM call path (RFC #248 PR-1).

See ghantakiran/ShieldOps#248. This package is the ports-and-adapters
core that will sit behind the ``llm_structured`` shim. Production wires
Anthropic/Bedrock/Vertex/Azure providers + a heuristic classifier + the
RFC #246 evolution store as the fitness recorder. Tests wire
in-memory adapters and exercise the classify→route→record path in <10ms.

PR-1 lives in ``utils/llm_core`` (a sibling package to the existing
``utils/llm.py`` + ``utils/llm_router.py`` + ``utils/llm_providers.py``)
so it can land pure-additive. PR-2 turns ``utils/llm.py`` into a thin
shim that delegates to this orchestrator.
"""

from __future__ import annotations

from shieldops.utils.llm_core.composition import (
    build_in_memory_orchestrator,
    get_llm_orchestrator,
    set_llm_orchestrator,
    use_test_llm_orchestrator,
)
from shieldops.utils.llm_core.deps import LLMDeps
from shieldops.utils.llm_core.orchestrator import LLMOrchestrator
from shieldops.utils.llm_core.ports import (
    Clock,
    ComplexityClassifierPort,
    ContextRetrieverPort,
    FitnessRecorderPort,
    LLMProviderPort,
    Logger,
    RetryPolicyPort,
)
from shieldops.utils.llm_core.types import (
    Complexity,
    ContextChunk,
    LLMRequest,
    LLMResponse,
    LLMUnavailable,
    ModelTier,
    ProviderName,
    ProviderResult,
    RetryDecision,
    Sleep,
    Stop,
    TokenUsage,
)

__all__ = [
    "Clock",
    "Complexity",
    "ComplexityClassifierPort",
    "ContextChunk",
    "ContextRetrieverPort",
    "FitnessRecorderPort",
    "LLMDeps",
    "LLMOrchestrator",
    "LLMProviderPort",
    "LLMRequest",
    "LLMResponse",
    "LLMUnavailable",
    "Logger",
    "ModelTier",
    "ProviderName",
    "ProviderResult",
    "RetryDecision",
    "RetryPolicyPort",
    "Sleep",
    "Stop",
    "TokenUsage",
    "build_in_memory_orchestrator",
    "get_llm_orchestrator",
    "set_llm_orchestrator",
    "use_test_llm_orchestrator",
]
