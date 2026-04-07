"""LLMDeps — frozen dataclass bundling the 7 ports.

Same pattern as :class:`shieldops.api.policy.deps.PolicyDeps`. Adding
a new dependency is a deliberate schema change, not a silent subsystem
import.
"""

from __future__ import annotations

from dataclasses import dataclass

from shieldops.utils.llm_core.ports import (
    Clock,
    ComplexityClassifierPort,
    ContextRetrieverPort,
    FitnessRecorderPort,
    LLMProviderPort,
    Logger,
    ModelFor,
    RetryPolicyPort,
)
from shieldops.utils.llm_core.types import Complexity, ModelTier


def _default_model_table(complexity: Complexity) -> ModelTier:
    """Conservative default: HIGH → Opus, MEDIUM → Sonnet, LOW → Haiku."""
    return {
        Complexity.LOW: ModelTier.HAIKU,
        Complexity.MEDIUM: ModelTier.SONNET,
        Complexity.HIGH: ModelTier.OPUS,
    }[complexity]


@dataclass(frozen=True)
class LLMDeps:
    provider: LLMProviderPort
    classifier: ComplexityClassifierPort
    context: ContextRetrieverPort
    fitness: FitnessRecorderPort
    retry: RetryPolicyPort
    clock: Clock
    log: Logger
    model_for: ModelFor = _default_model_table
