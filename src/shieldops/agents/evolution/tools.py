"""Toolkit for the Evolution Engine Agent."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from shieldops.agents.evolution.models import (
    AgentGenome,
    DeploymentStatus,
    EvolutionCandidate,
    EvolutionDeployment,
    EvolutionStrategy,
    LearningPropagation,
    PromptMutation,
    ValidationResult,
)
from shieldops.utils.fitness_tracker import (
    FitnessDimension,
    FitnessTrend,
    get_fitness_tracker,
)
from shieldops.utils.learning_bus import (
    LearningEventType,
    LearningPriority,
    PropagationScope,
    get_learning_bus,
)
from shieldops.utils.prompt_evolution import (
    MutationType,
    get_prompt_store,
)

logger = structlog.get_logger()


class EvolutionToolkit:
    """Business logic for the evolution engine agent."""

    def __init__(self) -> None:
        self._fitness = get_fitness_tracker()
        self._prompts = get_prompt_store()
        self._bus = get_learning_bus()

    # ----- Fitness Measurement -----

    async def measure_fleet_fitness(
        self,
        target_agent_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Measure fitness across the fleet or specific agents."""
        leaderboard = self._fitness.get_leaderboard(top_n=100)
        stats = self._fitness.get_stats()

        if target_agent_ids:
            leaderboard = [e for e in leaderboard if e.agent_id in target_agent_ids]

        return {
            "leaderboard": [
                {
                    "agent_id": e.agent_id,
                    "agent_type": e.agent_type,
                    "composite_score": e.composite_score,
                    "strongest": e.strongest,
                    "weakest": e.weakest,
                    "trend": e.trend,
                    "generation": e.generation,
                }
                for e in leaderboard
            ],
            "fleet_stats": stats,
            "fleet_avg_fitness": stats.get("avg_composite", 0.0),
        }

    async def identify_candidates(
        self,
        max_candidates: int = 10,
        target_agent_ids: list[str] | None = None,
    ) -> list[EvolutionCandidate]:
        """Identify agents that are candidates for evolution."""
        candidates: list[EvolutionCandidate] = []

        # Get agents ready for evolution
        agent_ids = target_agent_ids or self._fitness.get_evolution_candidates()

        for agent_id in agent_ids[:max_candidates]:
            fitness = self._fitness.get_fitness(agent_id)
            if not fitness.dimensions:
                continue

            # Find weakest and strongest dimensions
            dims = fitness.dimensions
            weakest = min(dims, key=lambda d: dims[d].rolling_avg) if dims else ""
            strongest = max(dims, key=lambda d: dims[d].rolling_avg) if dims else ""

            # Determine strategy based on weakness
            strategy = self._suggest_strategy(weakest, fitness)

            # Determine improvement opportunity
            weakest_score = dims[weakest].rolling_avg if weakest else 0.0
            strongest_score = dims[strongest].rolling_avg if strongest else 0.0
            opportunity = (
                f"{weakest} at {weakest_score:.2f} vs {strongest} at {strongest_score:.2f}"
            )

            candidates.append(
                EvolutionCandidate(
                    agent_id=agent_id,
                    agent_type=fitness.agent_type,
                    fitness_score=fitness.composite_score,
                    weakest_dimension=weakest,
                    strongest_dimension=strongest,
                    trend=fitness.evolution_readiness,
                    suggested_strategy=strategy,
                    improvement_opportunity=opportunity,
                    priority=self._priority_from_readiness(fitness.evolution_readiness),
                )
            )

        # Sort by priority (lower = more urgent)
        candidates.sort(key=lambda c: (c.priority, c.fitness_score))
        return candidates

    # ----- Genome Management -----

    async def capture_genome(self, agent_id: str) -> AgentGenome:
        """Capture the current genome (evolvable config) for an agent."""
        fitness = self._fitness.get_fitness(agent_id)

        # Collect active prompt versions
        prompt_versions: dict[str, str] = {}
        # In a real system, we'd query for this agent's specific prompts

        genome = AgentGenome(
            agent_id=agent_id,
            agent_type=fitness.agent_type,
            generation=fitness.generation,
            prompt_versions=prompt_versions,
            fitness_score=fitness.composite_score,
            created_at=time.time(),
            thresholds={
                "confidence_min": 0.5,
                "severity_threshold": 0.7,
                "false_positive_threshold": 0.3,
            },
            feature_flags={
                "memory_enrichment": True,
                "learning_bus": True,
                "auto_publish": True,
            },
        )
        return genome

    # ----- Prompt Evolution -----

    async def generate_mutation(
        self,
        agent_id: str,
        node_name: str,
        weakness: str,
        current_prompt: str = "",
    ) -> PromptMutation:
        """Generate a prompt mutation to address a weakness."""
        if not current_prompt:
            current_prompt = self._prompts.get_active_prompt(agent_id, node_name)

        # Determine mutation type from weakness
        mutation_type = self._mutation_type_from_weakness(weakness)

        return PromptMutation(
            agent_id=agent_id,
            node_name=node_name,
            current_prompt=current_prompt,
            proposed_prompt="",  # Will be filled by LLM in nodes.py
            mutation_type=mutation_type,
            reason=f"Address weakness in {weakness} dimension",
        )

    async def deploy_mutation(
        self,
        mutation: PromptMutation,
        dry_run: bool = False,
    ) -> EvolutionDeployment:
        """Deploy a prompt mutation (creates version + starts A/B test)."""
        deployment_id = f"evo_{uuid.uuid4().hex[:12]}"

        if dry_run:
            return EvolutionDeployment(
                deployment_id=deployment_id,
                agent_id=mutation.agent_id,
                strategy=EvolutionStrategy.PROMPT_REFINE,
                status=DeploymentStatus.PENDING,
                changes={"node": mutation.node_name, "mutation": mutation.mutation_type},
            )

        # Create mutated version in prompt store
        mt = MutationType(mutation.mutation_type)
        version = self._prompts.mutate(
            agent_id=mutation.agent_id,
            node_name=mutation.node_name,
            new_content=mutation.proposed_prompt,
            mutation_type=mt,
            reason=mutation.reason,
            auto_test=True,
        )

        return EvolutionDeployment(
            deployment_id=deployment_id,
            agent_id=mutation.agent_id,
            strategy=EvolutionStrategy.PROMPT_REFINE,
            status=DeploymentStatus.TESTING,
            changes={
                "node": mutation.node_name,
                "version_id": version.version_id,
                "generation": version.generation,
            },
            rollback_info={
                "parent_version": version.parent_version_id,
                "node": mutation.node_name,
            },
        )

    # ----- Learning Propagation -----

    async def propagate_learning(
        self,
        source_agent_id: str,
        source_agent_type: str,
        learning_type: str,
        title: str,
        description: str,
        payload: dict[str, Any] | None = None,
        scope: PropagationScope = PropagationScope.RELATED_TYPES,
    ) -> LearningPropagation:
        """Propagate a learning from one agent to others via the learning bus."""
        try:
            event_type = LearningEventType(learning_type)
        except ValueError:
            event_type = LearningEventType.PATTERN_DETECTED

        self._bus.publish(
            event_type=event_type,
            source_agent_id=source_agent_id,
            source_agent_type=source_agent_type,
            title=title,
            description=description,
            payload=payload or {},
            confidence=0.8,
            priority=LearningPriority.HIGH,
            scope=scope,
        )

        return LearningPropagation(
            source_agent_id=source_agent_id,
            learning_type=learning_type,
            description=description,
        )

    async def get_fleet_learnings(
        self,
        min_applications: int = 2,
    ) -> list[dict[str, Any]]:
        """Get learnings that have been widely applied across the fleet."""
        results: list[dict[str, Any]] = []
        for event_type in LearningEventType:
            patterns = self._bus.get_shared_patterns(
                event_type=event_type,
                min_applications=min_applications,
            )
            for p in patterns:
                results.append(
                    {
                        "event_id": p.event_id,
                        "type": p.event_type,
                        "title": p.title,
                        "source": p.source_agent_id,
                        "applied_by_count": len(p.applied_by),
                        "confidence": p.confidence,
                    }
                )
        return results

    # ----- Validation -----

    async def validate_deployment(
        self,
        deployment: EvolutionDeployment,
    ) -> ValidationResult:
        """Validate whether an evolution deployment improved the agent."""
        fitness = self._fitness.get_fitness(deployment.agent_id)

        # Compare current fitness to pre-evolution snapshot
        pre_fitness = deployment.changes.get("pre_fitness", fitness.composite_score)
        post_fitness = fitness.composite_score
        improvement = (post_fitness - pre_fitness) / max(pre_fitness, 0.01) * 100

        # Check for dimension regressions
        improved = []
        degraded = []
        for dim_name, dim_score in fitness.dimensions.items():
            if dim_score.trend == FitnessTrend.IMPROVING:
                improved.append(dim_name)
            elif dim_score.trend == FitnessTrend.DECLINING:
                degraded.append(dim_name)

        # Safety regression is always a fail
        safety_dim = fitness.dimensions.get(FitnessDimension.SAFETY)
        safety_regression = safety_dim is not None and safety_dim.trend == FitnessTrend.DECLINING

        if safety_regression:
            verdict = "ROLLBACK"
        elif improvement > 1:
            verdict = "KEEP"
        elif improvement < -5:
            verdict = "ROLLBACK"
        else:
            verdict = "MONITOR"

        return ValidationResult(
            deployment_id=deployment.deployment_id,
            agent_id=deployment.agent_id,
            pre_evolution_fitness=pre_fitness,
            post_evolution_fitness=post_fitness,
            improvement_pct=round(improvement, 2),
            regression_detected=safety_regression or improvement < -5,
            dimensions_improved=improved,
            dimensions_degraded=degraded,
            verdict=verdict,
        )

    async def rollback_deployment(
        self,
        deployment: EvolutionDeployment,
    ) -> bool:
        """Roll back an evolution deployment."""
        rollback = deployment.rollback_info
        if not rollback:
            return False

        node = rollback.get("node", "")
        if node:
            result = self._prompts.rollback(deployment.agent_id, node)
            if result:
                deployment.status = DeploymentStatus.ROLLED_BACK
                logger.info(
                    "evolution.rolled_back",
                    agent_id=deployment.agent_id,
                    deployment_id=deployment.deployment_id,
                )
                return True
        return False

    # ----- Internal -----

    def _suggest_strategy(self, weakest: str, fitness: Any) -> EvolutionStrategy:
        """Suggest evolution strategy based on weakest dimension."""
        strategy_map = {
            FitnessDimension.ACCURACY: EvolutionStrategy.PROMPT_REFINE,
            FitnessDimension.SPEED: EvolutionStrategy.WORKFLOW_ADJUST,
            FitnessDimension.COST: EvolutionStrategy.THRESHOLD_TUNE,
            FitnessDimension.SAFETY: EvolutionStrategy.CONTEXT_ENRICH,
            FitnessDimension.LEARNING_RATE: EvolutionStrategy.CROSS_POLLINATE,
        }
        try:
            return strategy_map.get(FitnessDimension(weakest), EvolutionStrategy.PROMPT_REFINE)
        except ValueError:
            return EvolutionStrategy.PROMPT_REFINE

    def _priority_from_readiness(self, readiness: str) -> int:
        """Convert evolution readiness to priority (1=highest)."""
        priority_map = {
            "declining": 1,
            "ready": 2,
            "needs_data": 4,
            "thriving": 5,
        }
        return priority_map.get(readiness, 3)

    def _mutation_type_from_weakness(self, weakness: str) -> str:
        """Map weakness dimension to appropriate mutation type."""
        mapping = {
            FitnessDimension.ACCURACY: MutationType.INSTRUCTION_REFINE,
            FitnessDimension.SPEED: MutationType.STRUCTURE_CHANGE,
            FitnessDimension.COST: MutationType.CONSTRAINT_ADD,
            FitnessDimension.SAFETY: MutationType.CONSTRAINT_ADD,
            FitnessDimension.LEARNING_RATE: MutationType.EXAMPLE_ADD,
        }
        try:
            return mapping.get(FitnessDimension(weakness), MutationType.LLM_REWRITE)
        except ValueError:
            return MutationType.LLM_REWRITE
