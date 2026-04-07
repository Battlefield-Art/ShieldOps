"""In-memory adapters for the LLM orchestrator ports.

Production adapters (``AnthropicProvider``, ``BedrockProvider``,
``HeuristicComplexityClassifier``, etc.) land in PR-2. PR-1 ships only
the test adapters so the contract tests can land immediately.
"""

from __future__ import annotations

from shieldops.utils.llm_core.adapters.capturing_logger import CapturingLogger
from shieldops.utils.llm_core.adapters.fake_provider import (
    FakeLLMProvider,
    ScriptedLLMProvider,
)
from shieldops.utils.llm_core.adapters.fixed_classifier import FixedClassifier
from shieldops.utils.llm_core.adapters.in_memory_fitness import (
    InMemoryFitnessRecorder,
)
from shieldops.utils.llm_core.adapters.manual_clock import ManualClock
from shieldops.utils.llm_core.adapters.null_logger import NullLogger
from shieldops.utils.llm_core.adapters.retry_policies import (
    NoRetry,
    ScriptedRetry,
)
from shieldops.utils.llm_core.adapters.static_context_retriever import (
    NullContextRetriever,
    StaticContextRetriever,
)

__all__ = [
    "CapturingLogger",
    "FakeLLMProvider",
    "FixedClassifier",
    "InMemoryFitnessRecorder",
    "ManualClock",
    "NoRetry",
    "NullContextRetriever",
    "NullLogger",
    "ScriptedLLMProvider",
    "ScriptedRetry",
    "StaticContextRetriever",
]
