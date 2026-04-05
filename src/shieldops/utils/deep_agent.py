"""Deep Agent Mixin — self-evolving lifecycle for LangGraph agents.

Provides pre_execute / post_execute hooks that wire agents into the
fitness tracker, memory store, prompt evolution, learning bus, and
reflection engine. Any agent runner can inherit DeepAgentMixin to
become self-evolving.

Usage:
    class MyAgentRunner(DeepAgentMixin):
        agent_type = "investigation"

        async def run(self, **kwargs):
            ctx = await self.pre_execute(kwargs)
            result = await self._run_graph(kwargs)
            await self.post_execute(ctx, result)
            return result
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.evolution_enums import (
    FitnessDimension,
    LearningEventType,
    LearningPriority,
    PropagationScope,
)
from shieldops.utils.evolution_service import EvolutionService

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Execution Context
# ---------------------------------------------------------------------------


class ExecutionContext(BaseModel):
    """Context captured during pre_execute, consumed during post_execute."""

    execution_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    agent_id: str = ""
    agent_type: str = ""
    started_at: float = Field(default_factory=time.time)
    enriched_context: dict[str, Any] = Field(default_factory=dict)
    memory_hits: list[dict[str, Any]] = Field(default_factory=list)
    learning_events_received: list[str] = Field(default_factory=list)
    active_prompt_versions: dict[str, str] = Field(default_factory=dict)
    fitness_snapshot: dict[str, float] = Field(default_factory=dict)


class ExecutionOutcome(BaseModel):
    """Structured outcome of an agent execution for fitness tracking."""

    success: bool = True
    accuracy_signal: float = 0.5
    duration_ms: int = 0
    cost_tokens: int = 0
    safety_violations: int = 0
    false_positive: bool = False
    actions_taken: int = 0
    confidence: float = 0.5
    error: str = ""
    learnings: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Deep Agent Mixin
# ---------------------------------------------------------------------------


class DeepAgentMixin:
    """Mixin that gives any agent self-evolving capabilities.

    Subclasses should set `agent_type` and call pre_execute/post_execute
    around their graph execution.
    """

    agent_type: str = "unknown"
    _agent_id: str = ""

    # Feature flags for gradual rollout
    enable_memory_enrichment: bool = True
    enable_learning_bus: bool = True
    enable_fitness_tracking: bool = True
    enable_prompt_evolution: bool = True
    enable_auto_publish: bool = True

    def __init__(self, agent_id: str = "", **kwargs: Any) -> None:
        self._agent_id = agent_id or f"{self.agent_type}_{uuid.uuid4().hex[:8]}"
        self._evo = EvolutionService()
        self._execution_count: int = 0
        self._cumulative_accuracy: float = 0.0

        # Auto-subscribe to learning bus
        if self.enable_learning_bus:
            self._evo.learning.subscribe(
                subscriber_id=self._agent_id,
                subscriber_type=self.agent_type,
                min_confidence=0.3,
            )

        super().__init__(**kwargs)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    # ----- Pre-Execution -----

    async def pre_execute(
        self,
        inputs: dict[str, Any],
        node_names: list[str] | None = None,
    ) -> ExecutionContext:
        """Pre-execution hook: enrich context, load memory, check fitness.

        Call this before running the agent graph. Returns an ExecutionContext
        that should be passed to post_execute.
        """
        ctx = ExecutionContext(
            agent_id=self._agent_id,
            agent_type=self.agent_type,
        )

        # 1. Capture current fitness snapshot
        if self.enable_fitness_tracking:
            fitness = self._evo.fitness.get_fitness(self._agent_id)
            ctx.fitness_snapshot = {
                dim: score.rolling_avg for dim, score in fitness.dimensions.items()
            }

        # 2. Retrieve relevant memories
        if self.enable_memory_enrichment:
            ctx.memory_hits = await self._query_memories(inputs)

        # 3. Check for pending learning events
        if self.enable_learning_bus:
            pending = self._evo.learning.get_pending(
                subscriber_id=self._agent_id,
                limit=10,
            )
            ctx.learning_events_received = [e.event_id for e in pending]
            ctx.enriched_context["learning_events"] = [
                {
                    "type": e.event_type,
                    "title": e.title,
                    "payload": e.payload,
                    "confidence": e.confidence,
                }
                for e in pending
            ]

        # 4. Load active prompt versions
        if self.enable_prompt_evolution and node_names:
            for node_name in node_names:
                version = self._evo.prompts.get_active_version(self._agent_id, node_name)
                if version:
                    ctx.active_prompt_versions[node_name] = version.version_id

        logger.info(
            "deep_agent.pre_execute",
            agent_id=self._agent_id,
            agent_type=self.agent_type,
            memory_hits=len(ctx.memory_hits),
            pending_learnings=len(ctx.learning_events_received),
        )
        return ctx

    # ----- Post-Execution -----

    async def post_execute(
        self,
        ctx: ExecutionContext,
        outcome: ExecutionOutcome,
    ) -> dict[str, Any]:
        """Post-execution hook: record fitness, publish learnings, update prompts.

        Call this after the agent graph completes.
        """
        duration_ms = int((time.time() - ctx.started_at) * 1000)
        outcome.duration_ms = outcome.duration_ms or duration_ms
        self._execution_count += 1

        results: dict[str, Any] = {
            "execution_id": ctx.execution_id,
            "duration_ms": duration_ms,
        }

        # 1. Record fitness observations
        if self.enable_fitness_tracking:
            self._record_fitness(outcome)
            results["fitness"] = self._evo.fitness.get_fitness(self._agent_id).composite_score

        # 2. Update prompt performance scores
        if self.enable_prompt_evolution:
            for node_name, version_id in ctx.active_prompt_versions.items():
                self._evo.prompts.record_ab_observation(
                    agent_id=self._agent_id,
                    node_name=node_name,
                    version_id=version_id,
                    score=outcome.accuracy_signal,
                )

        # 3. Publish learnings to the bus
        if self.enable_auto_publish and outcome.learnings:
            published = self._publish_learnings(outcome)
            results["learnings_published"] = published

        # 4. Mark learning events as applied/rejected
        if self.enable_learning_bus:
            for event_id in ctx.learning_events_received:
                if outcome.success:
                    self._evo.learning.mark_applied(event_id, self._agent_id)
                else:
                    self._evo.learning.mark_rejected(event_id, self._agent_id)

        # 5. Track cumulative learning rate
        self._cumulative_accuracy = (
            self._cumulative_accuracy * (self._execution_count - 1) + outcome.accuracy_signal
        ) / self._execution_count

        logger.info(
            "deep_agent.post_execute",
            agent_id=self._agent_id,
            agent_type=self.agent_type,
            success=outcome.success,
            accuracy=round(outcome.accuracy_signal, 4),
            duration_ms=duration_ms,
            execution_count=self._execution_count,
        )
        return results

    # ----- Evolution -----

    async def evolve(
        self,
        node_name: str,
        new_prompt: str,
        mutation_type: str = "llm_rewrite",
        reason: str = "",
    ) -> dict[str, Any]:
        """Trigger a prompt mutation for a specific node.

        Creates a new prompt version and starts A/B testing against the
        current champion.
        """
        from shieldops.utils.evolution_enums import MutationType

        mt = MutationType(mutation_type)
        version = self._evo.prompts.mutate(
            agent_id=self._agent_id,
            node_name=node_name,
            new_content=new_prompt,
            mutation_type=mt,
            reason=reason,
        )

        # Record evolution in fitness tracker
        gen = self._evo.fitness.mark_evolved(self._agent_id)

        logger.info(
            "deep_agent.evolved",
            agent_id=self._agent_id,
            node=node_name,
            generation=gen,
            mutation=mutation_type,
        )
        return {
            "version_id": version.version_id,
            "generation": gen,
            "status": version.status,
        }

    def get_fitness(self) -> dict[str, Any]:
        """Get current fitness profile as a dict."""
        f = self._evo.fitness.get_fitness(self._agent_id)
        return {
            "agent_id": f.agent_id,
            "composite_score": f.composite_score,
            "generation": f.generation,
            "evolution_readiness": f.evolution_readiness,
            "dimensions": {
                dim: {
                    "current": ds.current,
                    "rolling_avg": ds.rolling_avg,
                    "trend": ds.trend,
                }
                for dim, ds in f.dimensions.items()
            },
        }

    def get_evolution_status(self) -> dict[str, Any]:
        """Get combined evolution status: fitness + prompts + learning."""
        fitness = self._evo.fitness.get_fitness(self._agent_id)
        pending = self._evo.learning.get_pending(self._agent_id, limit=5)

        return {
            "agent_id": self._agent_id,
            "agent_type": self.agent_type,
            "generation": fitness.generation,
            "composite_fitness": fitness.composite_score,
            "evolution_readiness": fitness.evolution_readiness,
            "execution_count": self._execution_count,
            "cumulative_accuracy": round(self._cumulative_accuracy, 4),
            "pending_learnings": len(pending),
            "prompt_stats": self._evo.prompts.get_stats(),
        }

    # ----- Internal -----

    async def _query_memories(self, inputs: dict[str, Any]) -> list[dict[str, Any]]:
        """Query memory store for relevant context. Override for custom queries."""
        # Default: extract entities from inputs for memory lookup
        entities: list[str] = []
        for key in ("target", "host", "ip", "user", "service", "alert_id"):
            val = inputs.get(key)
            if val and isinstance(val, str):
                entities.append(val)

        if not entities:
            return []

        # Use memory store toolkit directly (avoid circular imports)
        try:
            from shieldops.agents.agent_memory_store.tools import AgentMemoryStoreToolkit

            toolkit = AgentMemoryStoreToolkit()
            result = await toolkit.retrieve_memories(
                entities=entities,
                limit=5,
                min_importance=0.3,
            )
            return [
                {
                    "memory_id": m.memory_id,
                    "type": m.memory_type,
                    "content": m.content[:500],
                    "confidence": m.confidence,
                }
                for m in result.memories
            ]
        except Exception:
            logger.debug("deep_agent.memory_query_failed", agent_id=self._agent_id)
            return []

    def _record_fitness(self, outcome: ExecutionOutcome) -> None:
        """Map execution outcome to fitness dimensions."""
        tracker = self._evo.fitness

        # Accuracy: from the outcome signal
        tracker.record(
            self._agent_id,
            FitnessDimension.ACCURACY,
            outcome.accuracy_signal,
            agent_type=self.agent_type,
        )

        # Speed: normalize duration (target: <5s = 1.0, >60s = 0.0)
        speed = max(0.0, min(1.0, 1.0 - (outcome.duration_ms / 60_000)))
        tracker.record(
            self._agent_id,
            FitnessDimension.SPEED,
            speed,
            agent_type=self.agent_type,
        )

        # Cost: normalize tokens (target: <1000 = 1.0, >10000 = 0.0)
        if outcome.cost_tokens > 0:
            cost = max(0.0, min(1.0, 1.0 - (outcome.cost_tokens / 10_000)))
        else:
            cost = 0.8  # Unknown cost gets a decent default
        tracker.record(
            self._agent_id,
            FitnessDimension.COST,
            cost,
            agent_type=self.agent_type,
        )

        # Safety: 1.0 if no violations, degraded by each violation
        safety = max(0.0, 1.0 - outcome.safety_violations * 0.25)
        tracker.record(
            self._agent_id,
            FitnessDimension.SAFETY,
            safety,
            agent_type=self.agent_type,
        )

        # Learning rate: based on cumulative accuracy improvement
        if self._execution_count >= 5:
            # Compare recent accuracy to early accuracy
            lr = min(1.0, max(0.0, 0.5 + (outcome.accuracy_signal - self._cumulative_accuracy)))
        else:
            lr = 0.5  # Neutral until we have enough data
        tracker.record(
            self._agent_id,
            FitnessDimension.LEARNING_RATE,
            lr,
            agent_type=self.agent_type,
        )

    def _publish_learnings(self, outcome: ExecutionOutcome) -> int:
        """Publish execution learnings to the learning bus."""
        published = 0
        for learning in outcome.learnings:
            event_type = learning.get("type", LearningEventType.PATTERN_DETECTED)
            try:
                event_type = LearningEventType(event_type)
            except ValueError:
                event_type = LearningEventType.PATTERN_DETECTED

            self._evo.learning.publish(
                event_type=event_type,
                source_agent_id=self._agent_id,
                source_agent_type=self.agent_type,
                title=learning.get("title", ""),
                description=learning.get("description", ""),
                payload=learning.get("payload", {}),
                confidence=learning.get("confidence", outcome.confidence),
                priority=LearningPriority(learning.get("priority", LearningPriority.MEDIUM)),
                scope=PropagationScope(learning.get("scope", PropagationScope.SAME_TYPE)),
            )
            published += 1

        return published
