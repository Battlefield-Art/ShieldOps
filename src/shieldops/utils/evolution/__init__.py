"""Self-evolution subsystem — unified public surface.

See RFC #246 (ghantakiran/ShieldOps#246). This package replaces the
3-subsystem + facade + dead-mixin cluster in ``src/shieldops/utils/``
with a single :class:`EvolutionStore` that owns fitness, learning, and
prompt state, and one public write path :meth:`EvolutionStore.record_run`
that is the single source of truth for cross-subsystem integration.

Agent runners never touch the subsystems directly. They see only
:class:`RunOutcome` and the :class:`Evolution` Protocol handle returned
by :meth:`EvolutionStore.for_agent`.

PR-1 scope (what lives here today):
- ``EvolutionStore`` class with ``record_run`` orchestration body
- ``RunOutcome`` / ``Evolution`` types
- In-memory state for fitness / prompts / learning events
- ``use_test_evolution`` composition root
- Contract tests for: exception safety, cross-subsystem integration,
  multi-tenant isolation, leaderboard aggregation

PR-2+ migrates the existing ``fitness_tracker`` / ``learning_bus`` /
``prompt_evolution`` logic into the private ``_fitness`` / ``_learning``
/ ``_prompts`` modules under this package, behind the same public API.
"""

from __future__ import annotations

from shieldops.utils.evolution.composition import (
    get_evolution_store,
    set_evolution_store,
    use_test_evolution,
)
from shieldops.utils.evolution.store import (
    AgentScore,
    Evolution,
    EvolutionStore,
    LearningEvent,
    NullEvolution,
    PromptSelection,
    RunOutcome,
)
from shieldops.utils.evolution.types import (
    EvolutionConfig,
    FitnessDimension,
    FitnessObservation,
    LearningEventType,
    MutationType,
    PropagationScope,
)

__all__ = [
    "AgentScore",
    "Evolution",
    "EvolutionConfig",
    "EvolutionStore",
    "FitnessDimension",
    "FitnessObservation",
    "LearningEvent",
    "LearningEventType",
    "MutationType",
    "NullEvolution",
    "PromptSelection",
    "PropagationScope",
    "RunOutcome",
    "get_evolution_store",
    "set_evolution_store",
    "use_test_evolution",
]
