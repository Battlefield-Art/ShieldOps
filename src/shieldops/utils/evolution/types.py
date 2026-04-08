"""Public types for the evolution subsystem.

RFC #246 PR-7 (#280): this module is now the single source of truth for
every enum used by the evolution subsystem. The legacy shim at
``shieldops.utils.evolution_enums`` has been deleted; all callers import
from here.

The enums below are a strict union of the two historical sources:

1. The "new" :class:`EvolutionStore` subsystem (``evolution/store.py``),
   which drives PR-1..PR-6 of RFC #246.
2. The "legacy" ``fitness_tracker`` / ``learning_bus`` / ``prompt_evolution``
   subsystems still in use until PR-8 deletes them.

Where the two disagreed on member names (e.g.
``FitnessDimension.LEARNING`` vs ``LEARNING_RATE``), both members are
kept so each subsystem sees the names it expects.

Kept in a separate module so :class:`EvolutionStore` can import types
without pulling in any subsystem implementation code (keeps the import
graph flat and the module-level import cost minimal).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums — shared by both the new EvolutionStore and the legacy
# fitness_tracker / learning_bus / prompt_evolution subsystems.
# ---------------------------------------------------------------------------


class FitnessDimension(StrEnum):
    """Dimensions scored per agent run. Weights are in
    :class:`EvolutionConfig`.

    ``LEARNING`` is the canonical member; ``LEARNING_RATE`` is a
    StrEnum **alias** (same string value) kept for
    ``fitness_tracker`` / ``fitness_aggregator`` compatibility while
    PR-8 (#281) deletes those legacy modules. Because it is an alias
    iteration over ``FitnessDimension`` still yields exactly five
    canonical members, preserving the 5-dimension contract the legacy
    tests assert on.
    """

    ACCURACY = "accuracy"
    SAFETY = "safety"
    SPEED = "speed"
    LEARNING = "learning"
    COST = "cost"
    LEARNING_RATE = "learning"  # alias → LEARNING


class FitnessTrend(StrEnum):
    """Trend direction for a fitness dimension."""

    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    INSUFFICIENT_DATA = "insufficient_data"


class EvolutionReadiness(StrEnum):
    """Whether an agent is ready for evolution."""

    READY = "ready"
    NEEDS_DATA = "needs_data"
    DECLINING = "declining"
    THRIVING = "thriving"


class LearningEventType(StrEnum):
    """Categories of cross-agent learning events.

    Union of the new :class:`EvolutionStore` event taxonomy and the
    legacy ``learning_bus`` taxonomy.
    """

    # New EvolutionStore taxonomy.
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
    # Legacy learning_bus taxonomy.
    FALSE_POSITIVE_DISCOVERED = "false_positive_discovered"
    ATTACK_SIGNATURE_LEARNED = "attack_signature_learned"
    THRESHOLD_OPTIMIZED = "threshold_optimized"
    PLAYBOOK_IMPROVED = "playbook_improved"
    PATTERN_DETECTED = "pattern_detected"
    PROMPT_EVOLVED = "prompt_evolved"
    REMEDIATION_VALIDATED = "remediation_validated"
    ESCALATION_REFINED = "escalation_refined"
    DETECTION_RULE_TUNED = "detection_rule_tuned"
    CONTEXT_ENRICHED = "context_enriched"


class PropagationScope(StrEnum):
    """How widely a learning event should propagate.

    Union of the new and legacy scope taxonomies. ``SELF_ONLY`` and
    ``FLEET_WIDE`` are shared between both.
    """

    SELF_ONLY = "self_only"
    # New taxonomy.
    TEAM = "team"
    DOMAIN = "domain"
    # Legacy taxonomy.
    SAME_TYPE = "same_type"
    RELATED_TYPES = "related_types"
    FLEET_WIDE = "fleet_wide"


class LearningPriority(StrEnum):
    """Priority of learning propagation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MutationType(StrEnum):
    """How a prompt variant was produced.

    Union of the new :class:`EvolutionStore` mutation taxonomy and the
    legacy ``prompt_evolution`` taxonomy.
    """

    # New taxonomy.
    MANUAL = "manual"
    REPHRASE = "rephrase"
    SIMPLIFY = "simplify"
    ELABORATE = "elaborate"
    CONSTRAIN = "constrain"
    # Legacy taxonomy.
    ORIGINAL = "original"
    THRESHOLD_ADJUST = "threshold_adjust"
    INSTRUCTION_REFINE = "instruction_refine"
    EXAMPLE_ADD = "example_add"
    EXAMPLE_REMOVE = "example_remove"
    CONSTRAINT_ADD = "constraint_add"
    CONSTRAINT_RELAX = "constraint_relax"
    TONE_SHIFT = "tone_shift"
    STRUCTURE_CHANGE = "structure_change"
    LLM_REWRITE = "llm_rewrite"


class PromptStatus(StrEnum):
    """Lifecycle status of a prompt version."""

    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


class ABTestResult(StrEnum):
    """Outcome of an A/B test between two prompt versions."""

    CHALLENGER_WINS = "challenger_wins"
    CHAMPION_WINS = "champion_wins"
    NO_DIFFERENCE = "no_difference"
    INSUFFICIENT_DATA = "insufficient_data"


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
