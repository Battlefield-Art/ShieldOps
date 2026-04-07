"""Integration tests for the Evolution Engine Agent and Deep Agent infrastructure."""

from __future__ import annotations

import pytest

from shieldops.agents.evolution.models import (
    DeploymentStatus,
    EvolutionCandidate,
    EvolutionStage,
    EvolutionState,
    EvolutionStrategy,
)
from shieldops.agents.evolution.tools import EvolutionToolkit
from shieldops.utils.fitness_tracker import (
    EvolutionReadiness,
    FitnessDimension,
    FitnessTracker,
    FitnessTrend,
)
from shieldops.utils.learning_bus import (
    LearningBus,
    LearningEventType,
    LearningPriority,
    PropagationScope,
)
from shieldops.utils.prompt_evolution import (
    ABTestResult,
    MutationType,
    PromptEvolutionStore,
    PromptStatus,
)

# =====================================================================
# Fitness Tracker Tests
# =====================================================================


class TestFitnessTracker:
    """Tests for multi-dimensional fitness tracking."""

    def setup_method(self) -> None:
        self.tracker = FitnessTracker()

    def test_record_single_observation(self) -> None:
        obs = self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.85)
        assert obs.dimension == FitnessDimension.ACCURACY
        assert obs.value == 0.85

    def test_record_clamps_values(self) -> None:
        obs_high = self.tracker.record("agent_1", FitnessDimension.ACCURACY, 1.5)
        assert obs_high.value == 1.0
        obs_low = self.tracker.record("agent_1", FitnessDimension.ACCURACY, -0.5)
        assert obs_low.value == 0.0

    def test_composite_score_calculation(self) -> None:
        self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.9)
        self.tracker.record("agent_1", FitnessDimension.SPEED, 0.8)
        self.tracker.record("agent_1", FitnessDimension.COST, 0.7)
        self.tracker.record("agent_1", FitnessDimension.SAFETY, 0.95)
        self.tracker.record("agent_1", FitnessDimension.LEARNING_RATE, 0.6)

        fitness = self.tracker.get_fitness("agent_1")
        assert fitness.composite_score > 0
        assert fitness.composite_score <= 1.0
        assert len(fitness.dimensions) == 5

    def test_rolling_average(self) -> None:
        for i in range(10):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.5 + i * 0.05)

        fitness = self.tracker.get_fitness("agent_1")
        dim = fitness.dimensions[FitnessDimension.ACCURACY]
        assert dim.rolling_avg > 0.5
        assert dim.observation_count == 10
        assert dim.current == 0.95

    def test_trend_detection_improving(self) -> None:
        # First 5 low, next 5 high
        for _ in range(5):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.5)
        for _ in range(5):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.9)

        fitness = self.tracker.get_fitness("agent_1")
        dim = fitness.dimensions[FitnessDimension.ACCURACY]
        assert dim.trend == FitnessTrend.IMPROVING

    def test_trend_detection_declining(self) -> None:
        for _ in range(5):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.9)
        for _ in range(5):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.5)

        fitness = self.tracker.get_fitness("agent_1")
        dim = fitness.dimensions[FitnessDimension.ACCURACY]
        assert dim.trend == FitnessTrend.DECLINING

    def test_leaderboard(self) -> None:
        # Create 3 agents with different fitness
        for dim in FitnessDimension:
            self.tracker.record("agent_a", dim, 0.9)
            self.tracker.record("agent_b", dim, 0.7)
            self.tracker.record("agent_c", dim, 0.5)

        leaderboard = self.tracker.get_leaderboard(top_n=10)
        assert len(leaderboard) == 3
        assert leaderboard[0].agent_id == "agent_a"
        assert leaderboard[0].rank == 1
        assert leaderboard[2].agent_id == "agent_c"

    def test_evolution_candidates(self) -> None:
        # Agent with declining fitness should be a candidate
        for _ in range(5):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.9)
            self.tracker.record("agent_1", FitnessDimension.SAFETY, 0.9)
        for _ in range(5):
            self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.5)
            self.tracker.record("agent_1", FitnessDimension.SAFETY, 0.5)

        candidates = self.tracker.get_evolution_candidates()
        assert "agent_1" in candidates

    def test_mark_evolved(self) -> None:
        self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.8)
        gen = self.tracker.mark_evolved("agent_1")
        assert gen == 1
        fitness = self.tracker.get_fitness("agent_1")
        assert fitness.generation == 1
        assert fitness.evolution_readiness == EvolutionReadiness.THRIVING

    def test_rolling_window_eviction(self) -> None:
        tracker = FitnessTracker(rolling_window=5)
        for i in range(10):
            tracker.record("agent_1", FitnessDimension.ACCURACY, 0.1 * i)

        fitness = tracker.get_fitness("agent_1")
        dim = fitness.dimensions[FitnessDimension.ACCURACY]
        assert dim.observation_count == 5

    def test_stats(self) -> None:
        for dim in FitnessDimension:
            self.tracker.record("agent_1", dim, 0.8)
        stats = self.tracker.get_stats()
        assert stats["total_agents_tracked"] == 1
        assert stats["total_observations"] == 5

    def test_clear_agent(self) -> None:
        self.tracker.record("agent_1", FitnessDimension.ACCURACY, 0.8)
        self.tracker.clear_agent("agent_1")
        fitness = self.tracker.get_fitness("agent_1")
        assert fitness.total_observations == 0

    def test_record_batch(self) -> None:
        obs = self.tracker.record_batch(
            "agent_1",
            {FitnessDimension.ACCURACY: 0.9, FitnessDimension.SAFETY: 0.8},
        )
        assert len(obs) == 2


# =====================================================================
# Prompt Evolution Tests
# =====================================================================


class TestPromptEvolution:
    """Tests for prompt versioning, mutation, and A/B testing."""

    def setup_method(self) -> None:
        self.store = PromptEvolutionStore()

    def test_register_prompt(self) -> None:
        v = self.store.register_prompt("agent_1", "analyze", "You are a security analyst")
        assert v.status == PromptStatus.ACTIVE
        assert v.generation == 0

    def test_register_dedup(self) -> None:
        v1 = self.store.register_prompt("agent_1", "analyze", "prompt A")
        v2 = self.store.register_prompt("agent_1", "analyze", "prompt A")
        assert v1.version_id == v2.version_id

    def test_get_active_prompt(self) -> None:
        self.store.register_prompt("agent_1", "analyze", "prompt content")
        content = self.store.get_active_prompt("agent_1", "analyze")
        assert content == "prompt content"

    def test_mutate_creates_version(self) -> None:
        self.store.register_prompt("agent_1", "analyze", "original prompt")
        v2 = self.store.mutate(
            "agent_1",
            "analyze",
            "evolved prompt",
            MutationType.INSTRUCTION_REFINE,
            reason="test",
            auto_test=False,
        )
        assert v2.generation == 1
        assert v2.parent_version_id != ""
        assert v2.mutation_type == MutationType.INSTRUCTION_REFINE

    def test_mutate_with_ab_test(self) -> None:
        self.store.register_prompt("agent_1", "analyze", "original")
        self.store.mutate(
            "agent_1",
            "analyze",
            "evolved",
            MutationType.LLM_REWRITE,
            auto_test=True,
        )
        test = self.store.get_active_ab_test("agent_1", "analyze")
        assert test is not None
        assert test.result == ABTestResult.INSUFFICIENT_DATA

    def test_ab_test_challenger_wins(self) -> None:
        v1 = self.store.register_prompt("agent_1", "analyze", "original")
        v2 = self.store.mutate("agent_1", "analyze", "better", MutationType.LLM_REWRITE)

        test = self.store.get_active_ab_test("agent_1", "analyze")
        assert test is not None

        # Record observations: challenger consistently better
        for _ in range(10):
            self.store.record_ab_observation("agent_1", "analyze", v1.version_id, 0.6)
            self.store.record_ab_observation("agent_1", "analyze", v2.version_id, 0.9)

        test = self.store.get_active_ab_test("agent_1", "analyze")
        # After enough observations, test should conclude
        assert test is None or test.result != ABTestResult.INSUFFICIENT_DATA

        # Challenger should be active now
        active = self.store.get_active_prompt("agent_1", "analyze")
        assert active == "better"

    def test_rollback(self) -> None:
        self.store.register_prompt("agent_1", "analyze", "v1 content")
        self.store.mutate(
            "agent_1", "analyze", "v2 content", MutationType.LLM_REWRITE, auto_test=False
        )
        self.store.activate(
            "agent_1",
            "analyze",
            self.store.get_active_version("agent_1", "analyze").version_id
            if self.store.get_active_version("agent_1", "analyze")
            else "",
        )

        # Mutate again and activate
        v3 = self.store.mutate(
            "agent_1", "analyze", "v3 content", MutationType.LLM_REWRITE, auto_test=False
        )
        self.store.activate("agent_1", "analyze", v3.version_id)

        # Rollback
        result = self.store.rollback("agent_1", "analyze")
        assert result is not None
        active = self.store.get_active_prompt("agent_1", "analyze")
        assert active != "v3 content"

    def test_lineage(self) -> None:
        self.store.register_prompt("agent_1", "analyze", "v1")
        self.store.mutate(
            "agent_1", "analyze", "v2", MutationType.INSTRUCTION_REFINE, auto_test=False
        )
        self.store.mutate("agent_1", "analyze", "v3", MutationType.EXAMPLE_ADD, auto_test=False)

        lineage = self.store.get_lineage("agent_1", "analyze")
        assert lineage.total_versions == 3
        assert lineage.total_generations == 2

    def test_stats(self) -> None:
        self.store.register_prompt("agent_1", "analyze", "prompt")
        stats = self.store.get_stats()
        assert stats["total_prompts_tracked"] == 1
        assert stats["total_versions"] == 1


# =====================================================================
# Learning Bus Tests
# =====================================================================


class TestLearningBus:
    """Tests for cross-agent learning event propagation."""

    def setup_method(self) -> None:
        self.bus = LearningBus()

    def test_publish_event(self) -> None:
        event = self.bus.publish(
            event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Benign terraform refresh",
            confidence=0.9,
        )
        assert event.event_id != ""
        assert event.confidence == 0.9

    def test_subscribe_and_receive(self) -> None:
        received: list = []
        self.bus.subscribe(
            "agent_2",
            "soc_analyst",
            callback=lambda e: received.append(e),
        )
        self.bus.publish(
            event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Test learning",
            scope=PropagationScope.SAME_TYPE,
        )
        assert len(received) == 1

    def test_scope_filtering_same_type(self) -> None:
        received_same: list = []
        received_diff: list = []
        self.bus.subscribe("agent_2", "soc_analyst", callback=lambda e: received_same.append(e))
        self.bus.subscribe("agent_3", "remediation", callback=lambda e: received_diff.append(e))

        self.bus.publish(
            event_type=LearningEventType.PATTERN_DETECTED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="SOC pattern",
            scope=PropagationScope.SAME_TYPE,
        )
        assert len(received_same) == 1
        assert len(received_diff) == 0

    def test_scope_fleet_wide(self) -> None:
        received: list = []
        self.bus.subscribe("agent_2", "remediation", callback=lambda e: received.append(e))

        self.bus.publish(
            event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="New attack sig",
            scope=PropagationScope.FLEET_WIDE,
        )
        assert len(received) == 1

    def test_mark_applied_rejected(self) -> None:
        event = self.bus.publish(
            event_type=LearningEventType.THRESHOLD_OPTIMIZED,
            source_agent_id="agent_1",
            source_agent_type="detection",
            title="Threshold update",
        )
        self.bus.mark_applied(event.event_id, "agent_2")
        self.bus.mark_rejected(event.event_id, "agent_3")

        report = self.bus.get_propagation_report(event.event_id)
        assert report is not None
        assert report.total_applied == 1
        assert report.total_rejected == 1

    def test_get_pending(self) -> None:
        self.bus.subscribe("agent_2", "soc_analyst")
        self.bus.publish(
            event_type=LearningEventType.PATTERN_DETECTED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Pending learning",
            scope=PropagationScope.SAME_TYPE,
        )
        pending = self.bus.get_pending("agent_2")
        assert len(pending) == 1

    def test_no_self_delivery(self) -> None:
        self.bus.subscribe("agent_1", "soc_analyst")
        self.bus.publish(
            event_type=LearningEventType.PATTERN_DETECTED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Self-published",
            scope=PropagationScope.FLEET_WIDE,
        )
        pending = self.bus.get_pending("agent_1")
        assert len(pending) == 0

    def test_priority_filtering(self) -> None:
        received: list = []
        self.bus.subscribe(
            "agent_2",
            "soc_analyst",
            min_priority=LearningPriority.HIGH,
            callback=lambda e: received.append(e),
        )
        self.bus.publish(
            event_type=LearningEventType.PATTERN_DETECTED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Low priority",
            priority=LearningPriority.LOW,
            scope=PropagationScope.SAME_TYPE,
        )
        assert len(received) == 0

    def test_shared_patterns(self) -> None:
        event = self.bus.publish(
            event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Widely applied FP",
        )
        for i in range(5):
            self.bus.mark_applied(event.event_id, f"agent_{i + 2}")

        patterns = self.bus.get_shared_patterns(min_applications=3)
        assert len(patterns) == 1

    def test_stats(self) -> None:
        self.bus.subscribe("agent_2", "soc_analyst")
        self.bus.publish(
            event_type=LearningEventType.PATTERN_DETECTED,
            source_agent_id="agent_1",
            source_agent_type="soc_analyst",
            title="Test",
        )
        stats = self.bus.get_stats()
        assert stats["total_events"] == 1
        assert stats["total_subscribers"] == 1

    def test_unsubscribe(self) -> None:
        self.bus.subscribe("agent_2", "soc_analyst")
        assert self.bus.unsubscribe("agent_2")
        assert not self.bus.unsubscribe("nonexistent")


# =====================================================================
# Evolution Toolkit Tests
# =====================================================================


class TestEvolutionToolkit:
    """Tests for the evolution toolkit business logic."""

    def setup_method(self) -> None:
        self.toolkit = EvolutionToolkit()
        # Seed some fitness data
        tracker = self.toolkit._fitness
        for dim in FitnessDimension:
            for _ in range(6):
                tracker.record("agent_a", dim, 0.9, agent_type="investigation")
                tracker.record("agent_b", dim, 0.6, agent_type="soc_analyst")
            # Make agent_b declining
            for _ in range(6):
                tracker.record("agent_b", dim, 0.4, agent_type="soc_analyst")

    @pytest.mark.asyncio
    async def test_measure_fleet_fitness(self) -> None:
        result = await self.toolkit.measure_fleet_fitness()
        assert "leaderboard" in result
        assert "fleet_avg_fitness" in result

    @pytest.mark.asyncio
    async def test_identify_candidates(self) -> None:
        candidates = await self.toolkit.identify_candidates(max_candidates=5)
        assert isinstance(candidates, list)
        # agent_b should be a candidate (declining)
        agent_ids = [c.agent_id for c in candidates]
        assert "agent_b" in agent_ids

    @pytest.mark.asyncio
    async def test_capture_genome(self) -> None:
        genome = await self.toolkit.capture_genome("agent_a")
        assert genome.agent_id == "agent_a"
        assert genome.agent_type == "investigation"

    @pytest.mark.asyncio
    async def test_generate_mutation(self) -> None:
        # Register a prompt first
        self.toolkit._prompts.register_prompt("agent_a", "primary", "Original prompt")
        mutation = await self.toolkit.generate_mutation("agent_a", "primary", "accuracy")
        assert mutation.agent_id == "agent_a"
        assert mutation.current_prompt == "Original prompt"

    @pytest.mark.asyncio
    async def test_deploy_mutation_dry_run(self) -> None:
        from shieldops.agents.evolution.models import PromptMutation

        mutation = PromptMutation(
            agent_id="agent_a",
            node_name="primary",
            proposed_prompt="Evolved prompt",
        )
        deployment = await self.toolkit.deploy_mutation(mutation, dry_run=True)
        assert deployment.status == DeploymentStatus.PENDING

    @pytest.mark.asyncio
    async def test_validate_deployment(self) -> None:
        from shieldops.agents.evolution.models import EvolutionDeployment

        deployment = EvolutionDeployment(
            deployment_id="test_dep_1",
            agent_id="agent_a",
            changes={"pre_fitness": 0.85},
        )
        result = await self.toolkit.validate_deployment(deployment)
        assert result.verdict in ("KEEP", "ROLLBACK", "MONITOR")

    @pytest.mark.asyncio
    async def test_propagate_learning(self) -> None:
        prop = await self.toolkit.propagate_learning(
            source_agent_id="agent_a",
            source_agent_type="investigation",
            learning_type="pattern_detected",
            title="Test propagation",
            description="Test learning",
        )
        assert prop.source_agent_id == "agent_a"

    @pytest.mark.asyncio
    async def test_get_fleet_learnings(self) -> None:
        learnings = await self.toolkit.get_fleet_learnings(min_applications=0)
        assert isinstance(learnings, list)


# =====================================================================
# Evolution State Model Tests
# =====================================================================


class TestEvolutionModels:
    """Tests for evolution state and domain models."""

    def test_evolution_state_defaults(self) -> None:
        state = EvolutionState()
        assert state.stage == EvolutionStage.MEASURE_FITNESS
        assert state.total_candidates == 0
        assert state.error == ""

    def test_agent_genome(self) -> None:
        from shieldops.agents.evolution.models import AgentGenome

        genome = AgentGenome(
            agent_id="test",
            agent_type="investigation",
            generation=3,
            thresholds={"confidence": 0.85},
        )
        assert genome.generation == 3
        assert genome.thresholds["confidence"] == 0.85

    def test_evolution_candidate(self) -> None:
        candidate = EvolutionCandidate(
            agent_id="test",
            fitness_score=0.72,
            suggested_strategy=EvolutionStrategy.PROMPT_REFINE,
        )
        assert candidate.suggested_strategy == EvolutionStrategy.PROMPT_REFINE
