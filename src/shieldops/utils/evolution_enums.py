"""Shared enums for the self-evolution subsystem.

Extracted from fitness_tracker, learning_bus, and prompt_evolution so that
lightweight consumers can import enum types without pulling in heavy
subsystem singletons.
"""

from __future__ import annotations

from enum import StrEnum

# ---------------------------------------------------------------------------
# fitness_tracker enums
# ---------------------------------------------------------------------------


class FitnessDimension(StrEnum):
    """The five dimensions of agent fitness."""

    ACCURACY = "accuracy"
    SPEED = "speed"
    COST = "cost"
    SAFETY = "safety"
    LEARNING_RATE = "learning_rate"


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


# ---------------------------------------------------------------------------
# learning_bus enums
# ---------------------------------------------------------------------------


class LearningEventType(StrEnum):
    """Categories of cross-agent learning events."""

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
    """How widely a learning event should propagate."""

    SELF_ONLY = "self_only"
    SAME_TYPE = "same_type"
    RELATED_TYPES = "related_types"
    FLEET_WIDE = "fleet_wide"


class LearningPriority(StrEnum):
    """Priority of learning propagation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# prompt_evolution enums
# ---------------------------------------------------------------------------


class MutationType(StrEnum):
    """How a prompt was mutated from its parent."""

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
