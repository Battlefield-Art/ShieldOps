"""Public types for the evolution subsystem.

Renamed from the circular-import workaround ``evolution_enums.py``.
These types are the public type surface agents see; the legacy StrEnums
stay compatible so the existing ``utils/evolution_enums.py`` re-export
shim keeps working during PR-1.

Kept in a separate module so ``EvolutionStore`` can import types without
pulling in any subsystem implementation code (keeps the import graph flat
and the module-level import cost minimal).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums — the same ones in utils/evolution_enums.py, re-homed here.
# The old module will re-export from this module in PR-5.
# ---------------------------------------------------------------------------


class FitnessDimension(StrEnum):
    """Five dimensions scored per agent run. Weights are in
    :class:`EvolutionConfig`."""

    ACCURACY = "accuracy"
    SAFETY = "safety"
    SPEED = "speed"
    LEARNING = "learning"
    COST = "cost"


class LearningEventType(StrEnum):
    AGENT_EXECUTED = "agent.executed"
    FITNESS_OBSERVED = "fitness.observed"
    FITNESS_TREND_SHIFTED = "fitness.trend_shifted"
    PROMPT_VARIANT_PROPOSED = "prompt.variant_proposed"
    PROMPT_VARIANT_PROMOTED = "prompt.variant_promoted"
    PROMPT_VARIANT_DEMOTED = "prompt.variant_demoted"
    POLICY_VIOLATION = "policy.violation"
    INSIGHT_DISCOVERED = "insight.discovered"
    ANOMALY_DETECTED = "anomaly.detected"
    FLEET_BROADCAST = "fleet.broadcast"


class PropagationScope(StrEnum):
    SELF_ONLY = "self_only"
    TEAM = "team"
    DOMAIN = "domain"
    FLEET_WIDE = "fleet_wide"


class MutationType(StrEnum):
    """How a prompt variant was produced."""

    MANUAL = "manual"
    REPHRASE = "rephrase"
    SIMPLIFY = "simplify"
    ELABORATE = "elaborate"
    CONSTRAIN = "constrain"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FitnessObservation(BaseModel):
    """One recorded observation of an agent run.

    Promoted from the private type inside ``fitness_tracker.py`` to the
    public type surface in PR-1 so external callers (``record_run``) can
    construct one without touching the tracker internals.
    """

    agent_id: str
    accuracy: float = 0.0
    safety: float = 1.0
    speed: float = 1.0
    learning: float = 0.0
    cost: float = 1.0

    def score(self, config: EvolutionConfig) -> float:
        """Weighted combination using the config's fitness weights."""
        w = config.fitness_weights
        return (
            w.accuracy * self.accuracy
            + w.safety * self.safety
            + w.speed * self.speed
            + w.learning * self.learning
            + w.cost * self.cost
        )


class FitnessWeights(BaseModel):
    """Configurable weights on :class:`FitnessDimension`. Sum should be 1.0."""

    accuracy: float = 0.30
    safety: float = 0.30
    speed: float = 0.15
    learning: float = 0.15
    cost: float = 0.10


class EvolutionConfig(BaseModel):
    """Tunable knobs for the subsystem, matching the old
    ``fitness_tracker``/``prompt_evolution`` constants.
    """

    fitness_weights: FitnessWeights = Field(default_factory=FitnessWeights)
    mutation_threshold: float = 0.85
    """If an agent's rolling fitness crosses this, a prompt mutation is proposed."""

    ab_test_promotion_threshold: float = 0.05
    """Minimum fitness delta for a challenger to promote over champion."""

    window_size: int = 50
    """How many observations to keep per agent for rolling fitness."""
