"""Prompt Evolution — versioning, mutation, A/B testing, and lineage tracking.

Enables agents to evolve their system prompts over time based on reflection
outcomes. Tracks prompt lineage so any version can be inspected or rolled back.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Enums
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


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PromptVersion(BaseModel):
    """A versioned prompt with lineage tracking."""

    version_id: str = ""
    agent_id: str = ""
    node_name: str = ""
    content: str = ""
    parent_version_id: str = ""
    mutation_type: MutationType = MutationType.ORIGINAL
    mutation_reason: str = ""
    generation: int = 0
    status: PromptStatus = PromptStatus.DRAFT
    created_at: float = Field(default_factory=time.time)
    activated_at: float = 0.0
    deactivated_at: float = 0.0
    performance_score: float = 0.0
    observation_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ABTest(BaseModel):
    """An A/B test comparing two prompt versions."""

    test_id: str = ""
    agent_id: str = ""
    node_name: str = ""
    champion_id: str = ""
    challenger_id: str = ""
    champion_score: float = 0.0
    challenger_score: float = 0.0
    champion_observations: int = 0
    challenger_observations: int = 0
    result: ABTestResult = ABTestResult.INSUFFICIENT_DATA
    started_at: float = Field(default_factory=time.time)
    concluded_at: float = 0.0
    min_observations: int = 10


class PromptLineage(BaseModel):
    """Full lineage tree for an agent's prompts at a specific node."""

    agent_id: str = ""
    node_name: str = ""
    active_version_id: str = ""
    total_versions: int = 0
    total_generations: int = 0
    versions: list[PromptVersion] = Field(default_factory=list)
    improvement_rate: float = 0.0


# ---------------------------------------------------------------------------
# Prompt Evolution Store
# ---------------------------------------------------------------------------

MAX_VERSIONS_PER_PROMPT = 100
MIN_AB_OBSERVATIONS = 10
AB_SIGNIFICANCE_THRESHOLD = 0.05  # 5% improvement required to declare winner


class PromptEvolutionStore:
    """Manages prompt versioning, mutation, A/B testing, and lineage.

    Each prompt is keyed by (agent_id, node_name) — an agent can have
    different prompts evolving independently for each node.
    """

    def __init__(self) -> None:
        # (agent_id, node_name) → list[PromptVersion]
        self._versions: dict[tuple[str, str], list[PromptVersion]] = defaultdict(list)
        # (agent_id, node_name) → active version_id
        self._active: dict[tuple[str, str], str] = {}
        # test_id → ABTest
        self._ab_tests: dict[str, ABTest] = {}
        # (agent_id, node_name) → generation counter
        self._generations: dict[tuple[str, str], int] = defaultdict(int)

    # ----- Version Management -----

    def register_prompt(
        self,
        agent_id: str,
        node_name: str,
        content: str,
        activate: bool = True,
    ) -> PromptVersion:
        """Register the initial prompt for an agent node."""
        key = (agent_id, node_name)
        version_id = self._hash(agent_id, node_name, content, 0)

        # Don't duplicate if identical content already registered
        for v in self._versions[key]:
            if v.content == content:
                return v

        version = PromptVersion(
            version_id=version_id,
            agent_id=agent_id,
            node_name=node_name,
            content=content,
            generation=0,
            status=PromptStatus.ACTIVE if activate else PromptStatus.DRAFT,
            activated_at=time.time() if activate else 0.0,
        )
        self._versions[key].append(version)
        if activate:
            self._active[key] = version_id

        logger.info(
            "prompt.registered",
            agent_id=agent_id,
            node=node_name,
            version=version_id[:12],
        )
        return version

    def mutate(
        self,
        agent_id: str,
        node_name: str,
        new_content: str,
        mutation_type: MutationType,
        reason: str = "",
        auto_test: bool = True,
    ) -> PromptVersion:
        """Create a mutated version of the active prompt.

        If auto_test is True, the new version enters A/B testing against
        the current champion. Otherwise it becomes a draft.
        """
        key = (agent_id, node_name)
        self._generations[key] += 1
        gen = self._generations[key]
        parent_id = self._active.get(key, "")

        version_id = self._hash(agent_id, node_name, new_content, gen)
        status = PromptStatus.TESTING if auto_test else PromptStatus.DRAFT

        version = PromptVersion(
            version_id=version_id,
            agent_id=agent_id,
            node_name=node_name,
            content=new_content,
            parent_version_id=parent_id,
            mutation_type=mutation_type,
            mutation_reason=reason,
            generation=gen,
            status=status,
        )

        versions = self._versions[key]
        versions.append(version)
        # Evict oldest superseded versions if over limit
        if len(versions) > MAX_VERSIONS_PER_PROMPT:
            self._versions[key] = [
                v
                for v in versions
                if v.status not in (PromptStatus.SUPERSEDED, PromptStatus.ROLLED_BACK)
            ][-MAX_VERSIONS_PER_PROMPT:]

        # Start A/B test if requested
        if auto_test and parent_id:
            self._start_ab_test(agent_id, node_name, parent_id, version_id)

        logger.info(
            "prompt.mutated",
            agent_id=agent_id,
            node=node_name,
            mutation=mutation_type,
            generation=gen,
            version=version_id[:12],
        )
        return version

    def get_active_prompt(self, agent_id: str, node_name: str) -> str:
        """Get the currently active prompt content for an agent node."""
        key = (agent_id, node_name)
        version_id = self._active.get(key)
        if not version_id:
            return ""
        for v in self._versions[key]:
            if v.version_id == version_id:
                return v.content
        return ""

    def get_active_version(self, agent_id: str, node_name: str) -> PromptVersion | None:
        """Get the currently active PromptVersion for an agent node."""
        key = (agent_id, node_name)
        version_id = self._active.get(key)
        if not version_id:
            return None
        for v in self._versions[key]:
            if v.version_id == version_id:
                return v
        return None

    def activate(self, agent_id: str, node_name: str, version_id: str) -> bool:
        """Activate a specific prompt version, superseding the current one."""
        key = (agent_id, node_name)
        target = None
        for v in self._versions[key]:
            if v.version_id == version_id:
                target = v
                break
        if not target:
            return False

        # Deactivate current
        old_id = self._active.get(key)
        if old_id:
            for v in self._versions[key]:
                if v.version_id == old_id:
                    v.status = PromptStatus.SUPERSEDED
                    v.deactivated_at = time.time()

        # Activate new
        target.status = PromptStatus.ACTIVE
        target.activated_at = time.time()
        self._active[key] = version_id

        logger.info(
            "prompt.activated",
            agent_id=agent_id,
            node=node_name,
            version=version_id[:12],
            superseded=old_id[:12] if old_id else "",
        )
        return True

    def rollback(self, agent_id: str, node_name: str) -> PromptVersion | None:
        """Roll back to the previous active prompt version."""
        key = (agent_id, node_name)
        current_id = self._active.get(key)
        if not current_id:
            return None

        # Find current version and its parent
        current = None
        for v in self._versions[key]:
            if v.version_id == current_id:
                current = v
                break

        if not current or not current.parent_version_id:
            return None

        # Mark current as rolled back
        current.status = PromptStatus.ROLLED_BACK
        current.deactivated_at = time.time()

        # Activate parent
        parent_id = current.parent_version_id
        for v in self._versions[key]:
            if v.version_id == parent_id:
                v.status = PromptStatus.ACTIVE
                v.activated_at = time.time()
                self._active[key] = parent_id
                logger.info(
                    "prompt.rolled_back",
                    agent_id=agent_id,
                    node=node_name,
                    from_version=current_id[:12],
                    to_version=parent_id[:12],
                )
                return v

        return None

    # ----- A/B Testing -----

    def record_ab_observation(
        self,
        agent_id: str,
        node_name: str,
        version_id: str,
        score: float,
    ) -> ABTestResult | None:
        """Record a performance observation for a version in an active A/B test.

        Returns the test result if the test has concluded, None otherwise.
        """
        # Find active test for this agent/node
        active_test = None
        for test in self._ab_tests.values():
            if (
                test.agent_id == agent_id
                and test.node_name == node_name
                and test.result == ABTestResult.INSUFFICIENT_DATA
            ):
                active_test = test
                break

        if not active_test:
            return None

        # Record observation
        if version_id == active_test.champion_id:
            n = active_test.champion_observations
            active_test.champion_score = (active_test.champion_score * n + score) / (n + 1)
            active_test.champion_observations += 1
        elif version_id == active_test.challenger_id:
            n = active_test.challenger_observations
            active_test.challenger_score = (active_test.challenger_score * n + score) / (n + 1)
            active_test.challenger_observations += 1
        else:
            return None

        # Check if we have enough data to conclude
        if (
            active_test.champion_observations >= active_test.min_observations
            and active_test.challenger_observations >= active_test.min_observations
        ):
            return self._conclude_ab_test(active_test)

        return None

    def get_active_ab_test(self, agent_id: str, node_name: str) -> ABTest | None:
        """Get the active A/B test for an agent node, if any."""
        for test in self._ab_tests.values():
            if (
                test.agent_id == agent_id
                and test.node_name == node_name
                and test.result == ABTestResult.INSUFFICIENT_DATA
            ):
                return test
        return None

    # ----- Lineage -----

    def get_lineage(self, agent_id: str, node_name: str) -> PromptLineage:
        """Get the full lineage for an agent node's prompts."""
        key = (agent_id, node_name)
        versions = self._versions.get(key, [])
        active_id = self._active.get(key, "")

        # Compute improvement rate
        scored = [v for v in versions if v.observation_count > 0]
        improvement_rate = 0.0
        if len(scored) >= 2:
            first_score = scored[0].performance_score
            last_score = scored[-1].performance_score
            if first_score > 0:
                improvement_rate = (last_score - first_score) / first_score

        return PromptLineage(
            agent_id=agent_id,
            node_name=node_name,
            active_version_id=active_id,
            total_versions=len(versions),
            total_generations=self._generations.get(key, 0),
            versions=versions,
            improvement_rate=round(improvement_rate, 4),
        )

    # ----- Stats -----

    def get_stats(self) -> dict[str, Any]:
        """Global prompt evolution statistics."""
        all_versions = [v for vlist in self._versions.values() for v in vlist]
        active_tests = [
            t for t in self._ab_tests.values() if t.result == ABTestResult.INSUFFICIENT_DATA
        ]
        concluded_tests = [
            t for t in self._ab_tests.values() if t.result != ABTestResult.INSUFFICIENT_DATA
        ]

        return {
            "total_prompts_tracked": len(self._versions),
            "total_versions": len(all_versions),
            "active_versions": sum(1 for v in all_versions if v.status == PromptStatus.ACTIVE),
            "total_mutations": sum(
                1 for v in all_versions if v.mutation_type != MutationType.ORIGINAL
            ),
            "active_ab_tests": len(active_tests),
            "concluded_ab_tests": len(concluded_tests),
            "challenger_win_rate": round(
                sum(1 for t in concluded_tests if t.result == ABTestResult.CHALLENGER_WINS)
                / max(len(concluded_tests), 1),
                4,
            ),
            "mutations_by_type": {
                mt: sum(1 for v in all_versions if v.mutation_type == mt)
                for mt in MutationType
                if sum(1 for v in all_versions if v.mutation_type == mt) > 0
            },
            "max_generation": max((g for g in self._generations.values()), default=0),
        }

    # ----- Internal -----

    def _hash(self, agent_id: str, node_name: str, content: str, gen: int) -> str:
        raw = f"{agent_id}:{node_name}:{gen}:{content[:200]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _start_ab_test(
        self,
        agent_id: str,
        node_name: str,
        champion_id: str,
        challenger_id: str,
    ) -> ABTest:
        test_id = f"ab_{agent_id}_{node_name}_{int(time.time())}"
        test = ABTest(
            test_id=test_id,
            agent_id=agent_id,
            node_name=node_name,
            champion_id=champion_id,
            challenger_id=challenger_id,
            min_observations=MIN_AB_OBSERVATIONS,
        )
        self._ab_tests[test_id] = test
        logger.info(
            "prompt.ab_test_started",
            agent_id=agent_id,
            node=node_name,
            champion=champion_id[:12],
            challenger=challenger_id[:12],
        )
        return test

    def _conclude_ab_test(self, test: ABTest) -> ABTestResult:
        delta = test.challenger_score - test.champion_score
        if delta > AB_SIGNIFICANCE_THRESHOLD:
            test.result = ABTestResult.CHALLENGER_WINS
            # Auto-promote challenger
            self.activate(test.agent_id, test.node_name, test.challenger_id)
        elif delta < -AB_SIGNIFICANCE_THRESHOLD:
            test.result = ABTestResult.CHAMPION_WINS
            # Mark challenger as superseded
            key = (test.agent_id, test.node_name)
            for v in self._versions[key]:
                if v.version_id == test.challenger_id:
                    v.status = PromptStatus.SUPERSEDED
        else:
            test.result = ABTestResult.NO_DIFFERENCE

        test.concluded_at = time.time()
        logger.info(
            "prompt.ab_test_concluded",
            agent_id=test.agent_id,
            node=test.node_name,
            result=test.result,
            champion_score=round(test.champion_score, 4),
            challenger_score=round(test.challenger_score, 4),
        )
        return test.result


# Module-level singleton
_store: PromptEvolutionStore | None = None


def get_prompt_store() -> PromptEvolutionStore:
    """Get or create the global prompt evolution store."""
    global _store
    if _store is None:
        _store = PromptEvolutionStore()
    return _store
