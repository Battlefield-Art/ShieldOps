"""Evolution Service — lazy facade over the 4 self-evolution subsystems.

Provides a single entry-point that delays importing the heavy subsystem
modules (fitness_tracker, learning_bus, prompt_evolution) until the
corresponding property is first accessed.  This keeps module-level import
cost near zero for code that only needs the lightweight enum types.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shieldops.utils.fitness_tracker import FitnessTracker
    from shieldops.utils.learning_bus import LearningBus
    from shieldops.utils.prompt_evolution import PromptEvolutionStore


class EvolutionService:
    """Lazy facade over the 4 self-evolution subsystems.

    Each property performs a deferred import and caches the singleton
    instance on first access, so downstream code pays zero import cost
    until it actually uses a subsystem.
    """

    @property
    def fitness(self) -> FitnessTracker:
        """Lazily load and cache the global FitnessTracker."""
        cached = self.__dict__.get("fitness")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        from shieldops.utils.fitness_tracker import get_fitness_tracker

        instance = get_fitness_tracker()
        self.__dict__["fitness"] = instance
        return instance  # type: ignore[no-any-return]

    @property
    def learning(self) -> LearningBus:
        """Lazily load and cache the global LearningBus."""
        cached = self.__dict__.get("learning")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        from shieldops.utils.learning_bus import get_learning_bus

        instance = get_learning_bus()
        self.__dict__["learning"] = instance
        return instance  # type: ignore[no-any-return]

    @property
    def prompts(self) -> PromptEvolutionStore:
        """Lazily load and cache the global PromptEvolutionStore."""
        cached = self.__dict__.get("prompts")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        from shieldops.utils.prompt_evolution import get_prompt_store

        instance = get_prompt_store()
        self.__dict__["prompts"] = instance
        return instance  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_service: EvolutionService | None = None


def get_evolution_service() -> EvolutionService:
    """Get or create the global EvolutionService."""
    global _service
    if _service is None:
        _service = EvolutionService()
    return _service
