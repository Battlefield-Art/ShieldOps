"""EvolutionStore — single owner of fitness + learning + prompts.

See RFC #246 (ghantakiran/ShieldOps#246). This module replaces the
``evolution_service.py`` facade + ``deep_agent.py`` mixin + wrapping
layers. The whole reason RFC #246 exists is that the three subsystems
never informed each other in production — this class is the explicit
cross-subsystem integration that ``DeepAgentMixin`` was supposed to be
but never was.

PR-1 scope: minimal in-memory implementations of fitness/prompts/learning
state, all owned by one :class:`EvolutionStore` instance. PR-2+ migrates
the existing 1,302 LOC of ``fitness_tracker`` / ``learning_bus`` /
``prompt_evolution`` into private modules inside this package.

The subtlest invariant — locked by
``test_record_run_exception_does_not_crash_caller`` — is that a failure
anywhere inside :meth:`EvolutionStore.record_run` is swallowed with a
structured log warning and a Prometheus-friendly counter. **A bug in
the integration must NEVER crash an agent run.**
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.evolution.types import (
    EvolutionConfig,
    FitnessDimension,
    FitnessObservation,
    LearningEventType,
    MutationType,
    PropagationScope,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Public value types
# ---------------------------------------------------------------------------


class RunOutcome(BaseModel):
    """What an agent runner knows after a run. Intentionally jargon-free.

    The author of an agent node fills this in and passes it to
    :meth:`Evolution.record`. The store maps it to a 5-dimensional
    :class:`FitnessObservation` internally.
    """

    success: bool
    latency_ms: float = 0.0
    tokens_used: int = 0
    cost_usd: float = 0.0
    helped: bool | None = None
    """Downstream feedback — e.g. user thumbs-up. ``None`` = no signal."""
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentScore(BaseModel):
    """A point on the leaderboard."""

    agent_id: str
    dimension: FitnessDimension
    value: float
    sample_count: int
    updated_at: datetime


class PromptSelection(BaseModel):
    """Returned by :meth:`Evolution.prompt` — a versioned prompt variant."""

    version_id: str
    template: str
    is_challenger: bool = False


class AgentStatus(StrEnum):
    """Lifecycle status for an agent tracked by :class:`EvolutionStore`.

    Kept intentionally independent of
    ``shieldops.db.models_agent_status.AgentLifecycleStatus`` so the store
    has no DB import dependency. PR-5 is responsible for mapping between
    the two at the repository boundary.
    """

    ACTIVE = "active"
    PROMOTED = "promoted"
    DEMOTED = "demoted"
    DISABLED = "disabled"


class DailyFitnessPoint(BaseModel):
    """One day's aggregated composite fitness inside a rolling window."""

    day_epoch: float
    composite: float
    dimensions: dict[str, float] = Field(default_factory=dict)
    sample_count: int = 0


class FitnessWindow(BaseModel):
    """Rolling-window view of an agent's composite fitness.

    Owned by :class:`EvolutionStore`; the deep module exposes this directly
    so the promotion route never needs a separate aggregator wrapper
    (RFC #246 PR-4 / PR-6).
    """

    agent_name: str
    window_days: int
    composite_current: float = 0.0
    composite_avg: float = 0.0
    min_composite: float = 0.0
    max_composite: float = 0.0
    sample_count: int = 0
    daily_points: list[DailyFitnessPoint] = Field(default_factory=list)


class AgentStatusSnapshot(BaseModel):
    """Per-agent lifecycle snapshot produced by
    :meth:`EvolutionStore.promote_agent` and
    :meth:`EvolutionStore.demote_agent`."""

    agent_name: str
    org_id: str = "default"
    status: AgentStatus = AgentStatus.ACTIVE
    current_fitness: float = 0.0
    promoted_at: datetime | None = None
    demoted_at: datetime | None = None
    reason: str = ""


@dataclass
class LearningEvent:
    """Event flowing through the internal learning bus. In PR-1 the bus
    is a simple list stored on :class:`EvolutionStore`. PR-2 migrates to
    the existing ``learning_bus.LearningBus``."""

    event_type: LearningEventType
    agent_id: str
    scope: PropagationScope = PropagationScope.SELF_ONLY
    payload: dict[str, Any] = field(default_factory=dict)
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Evolution Protocol — the bound view an agent runner sees
# ---------------------------------------------------------------------------


@runtime_checkable
class Evolution(Protocol):
    """Per-agent handle returned by :meth:`EvolutionStore.for_agent`.

    This is the interface the RFC #247 ``@define_agent`` framework
    wrapper uses. Agent authors never call the store directly; they see
    only this small surface.
    """

    def record(self, outcome: RunOutcome) -> None: ...
    def prompt(self) -> PromptSelection: ...
    def prompt_version(self) -> str: ...


class NullEvolution:
    """No-op Evolution handle — used as a default before any real store
    is installed, and in tests that don't care about evolution tracking.
    """

    def record(self, outcome: RunOutcome) -> None:
        return None

    def prompt(self) -> PromptSelection:
        return PromptSelection(version_id="null", template="")

    def prompt_version(self) -> str:
        return "null"


@dataclass
class _BoundEvolution:
    """Private implementation of :class:`Evolution` that delegates back
    to an :class:`EvolutionStore` for a specific ``(tenant_id, agent_id)``.
    """

    store: EvolutionStore
    agent_id: str
    tenant_id: str

    def record(self, outcome: RunOutcome) -> None:
        self.store.record_run(self.agent_id, outcome, tenant_id=self.tenant_id)

    def prompt(self) -> PromptSelection:
        return self.store.prompt_for(self.agent_id, tenant_id=self.tenant_id)

    def prompt_version(self) -> str:
        return self.prompt().version_id


# ---------------------------------------------------------------------------
# Internal in-memory state (PR-1). PR-2 will migrate to the existing
# fitness_tracker / learning_bus / prompt_evolution internals without
# changing the public surface.
# ---------------------------------------------------------------------------


@dataclass
class _FitnessState:
    """Rolling window of observations per (tenant, agent)."""

    observations: deque[FitnessObservation] = field(default_factory=lambda: deque(maxlen=50))
    timestamps: deque[datetime] = field(default_factory=lambda: deque(maxlen=50))

    def record(self, obs: FitnessObservation, *, ts: datetime) -> None:
        self.observations.append(obs)
        self.timestamps.append(ts)

    def score(self, config: EvolutionConfig) -> float:
        if not self.observations:
            return 0.0
        return sum(o.score(config) for o in self.observations) / len(self.observations)

    def dimension_average(self, dim: FitnessDimension) -> float:
        if not self.observations:
            return 0.0
        values = [getattr(o, dim.value) for o in self.observations]
        return sum(values) / len(values)


@dataclass
class _PromptState:
    """Per-agent prompt state: champion + optional challenger."""

    champion: PromptSelection = field(
        default_factory=lambda: PromptSelection(
            version_id="v1", template="default", is_challenger=False
        )
    )
    challenger: PromptSelection | None = None
    mutation_history: list[MutationType] = field(default_factory=list)


# ---------------------------------------------------------------------------
# EvolutionStore — the keystone
# ---------------------------------------------------------------------------


Clock = Callable[[], datetime]


def _default_clock() -> datetime:
    return datetime.now(UTC)


class EvolutionStore:
    """Single owner of fitness, learning, and prompt state.

    Construct one per process (single-tenant) or per tenant
    (multi-tenant). Test code uses :meth:`in_memory` to build a fresh
    isolated instance with no globals touched.
    """

    def __init__(
        self,
        *,
        config: EvolutionConfig | None = None,
        clock: Clock = _default_clock,
    ) -> None:
        self._config = config or EvolutionConfig()
        self._clock = clock

        # Keyed by (tenant_id, agent_id).
        self._fitness: dict[tuple[str, str], _FitnessState] = defaultdict(_FitnessState)
        self._prompts: dict[tuple[str, str], _PromptState] = defaultdict(_PromptState)
        self._learning: list[LearningEvent] = []
        # Keyed by (org_id, agent_name) — lifecycle snapshots for
        # promote_agent/demote_agent. Separate from tenant_id because the
        # promotion surface uses org_id in its public API (matching the
        # existing PromotionEngine contract).
        self._statuses: dict[tuple[str, str], AgentStatusSnapshot] = {}

        # Prometheus-friendly failure counters.
        self._record_run_errors: int = 0

        self._lock = threading.Lock()

    @classmethod
    def in_memory(cls) -> EvolutionStore:
        """Build a fresh isolated instance. Used by tests."""
        return cls()

    # -- introspection --------------------------------------------------

    @property
    def config(self) -> EvolutionConfig:
        return self._config

    @property
    def record_run_error_count(self) -> int:
        """Number of times ``record_run`` swallowed an internal exception.
        Exposed so tests can assert on the exception-safety invariant."""
        return self._record_run_errors

    def learning_events(self, *, tenant_id: str = "default") -> list[LearningEvent]:
        """Return all learning events, filtered by tenant if provided."""
        return [e for e in self._learning if e.payload.get("tenant_id", "default") == tenant_id]

    # -- the Evolution handle ------------------------------------------

    def for_agent(
        self,
        agent_id: str,
        *,
        tenant_id: str = "default",
    ) -> Evolution:
        """Return a per-agent handle. Cheap — no allocation penalty per
        call because it's a dataclass view, not a new subsystem copy."""
        return _BoundEvolution(store=self, agent_id=agent_id, tenant_id=tenant_id)

    # -- the SINGLE write path ------------------------------------------

    def record_run(
        self,
        agent_id: str,
        outcome: RunOutcome,
        *,
        tenant_id: str = "default",
    ) -> None:
        """The ~30-line cross-subsystem orchestration body.

        This is the single source of truth for how fitness, learning,
        and prompts inform each other. Every agent run flows through
        here via the ``@define_agent`` framework wrapper (RFC #247) or
        a manual ``evolution.record(outcome)`` call.

        Wrapped in a broad try/except by design — a bug in the
        integration must NEVER crash the calling agent. Failures are
        counted (:attr:`record_run_error_count`) and logged at warning
        level; they do not propagate.
        """
        try:
            self._record_run_impl(agent_id, outcome, tenant_id=tenant_id)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._record_run_errors += 1
            logger.warning(
                "evolution.record_run.failed",
                agent_id=agent_id,
                tenant_id=tenant_id,
                error=str(exc),
                error_count=self._record_run_errors,
            )

    def _record_run_impl(
        self,
        agent_id: str,
        outcome: RunOutcome,
        *,
        tenant_id: str,
    ) -> None:
        """The actual orchestration — deliberately small and sequential
        so the cross-subsystem contract is readable in one place."""
        key = (tenant_id, agent_id)

        # STEP 1: Map RunOutcome → FitnessObservation (5-dim)
        obs = self._outcome_to_observation(agent_id, outcome)

        # STEP 2: Record in the fitness window
        with self._lock:
            self._fitness[key].record(obs, ts=self._clock())
            current_score = self._fitness[key].score(self._config)

        # STEP 3: Emit a FITNESS_OBSERVED learning event
        self._publish_learning(
            LearningEvent(
                event_type=LearningEventType.FITNESS_OBSERVED,
                agent_id=agent_id,
                scope=PropagationScope.SELF_ONLY,
                payload={
                    "tenant_id": tenant_id,
                    "score": current_score,
                    "observation": obs.model_dump(),
                },
            )
        )

        # STEP 4: If fitness crosses the mutation threshold, propose a
        # new prompt variant. This is the integration DeepAgentMixin
        # was supposed to provide but never wired.
        if current_score >= self._config.mutation_threshold:
            self._propose_mutation(key)

        # STEP 5: If a challenger is active and we now have enough data
        # showing it wins by ab_test_promotion_threshold, promote it.
        self._maybe_promote_challenger(key, current_score)

    # -- subsystem helpers (PR-1 stubs; PR-2+ delegate to the real ones)

    def _outcome_to_observation(self, agent_id: str, outcome: RunOutcome) -> FitnessObservation:
        """Translate the jargon-free RunOutcome into the 5-dim space."""
        # Accuracy: 1.0 on success, 0.0 on failure
        accuracy = 1.0 if outcome.success else 0.0
        # Safety: 1.0 unless there's an explicit error that looks safety-relevant
        safety = 0.0 if (outcome.error and "safety" in outcome.error.lower()) else 1.0
        # Speed: inverse-latency, normalised so fast runs score near 1.0
        # (1000 ms → 0.5, 0 ms → 1.0, 5000 ms → ~0.17)
        speed = 1.0 / (1.0 + outcome.latency_ms / 1000.0)
        # Learning: +0.1 if downstream feedback says it helped, else 0.0
        learning = 0.1 if outcome.helped else 0.0
        # Cost: inverse-cost, 0 cost → 1.0, $1 → 0.5, $10 → ~0.09
        cost = 1.0 / (1.0 + outcome.cost_usd)
        return FitnessObservation(
            agent_id=agent_id,
            accuracy=accuracy,
            safety=safety,
            speed=speed,
            learning=learning,
            cost=cost,
        )

    def _publish_learning(self, event: LearningEvent) -> None:
        with self._lock:
            self._learning.append(event)

    def _propose_mutation(self, key: tuple[str, str]) -> None:
        tenant_id, agent_id = key
        with self._lock:
            state = self._prompts[key]
            if state.challenger is not None:
                return  # already running an A/B test
            # Propose a challenger (trivial mutation in PR-1)
            state.challenger = PromptSelection(
                version_id=f"{state.champion.version_id}-challenger",
                template=state.champion.template + " [challenger]",
                is_challenger=True,
            )
            state.mutation_history.append(MutationType.REPHRASE)

        self._publish_learning(
            LearningEvent(
                event_type=LearningEventType.PROMPT_VARIANT_PROPOSED,
                agent_id=agent_id,
                scope=PropagationScope.SELF_ONLY,
                payload={
                    "tenant_id": tenant_id,
                    "mutation": MutationType.REPHRASE.value,
                },
            )
        )

    def _maybe_promote_challenger(self, key: tuple[str, str], current_score: float) -> None:
        tenant_id, agent_id = key
        with self._lock:
            state = self._prompts[key]
            if state.challenger is None:
                return
            # PR-1 heuristic: if the agent's score is above the
            # promotion threshold, promote. Real promotion logic will
            # compare champion vs challenger specifically in PR-2.
            if (
                current_score
                < self._config.mutation_threshold + self._config.ab_test_promotion_threshold
            ):
                return
            old_version = state.champion.version_id
            state.champion = PromptSelection(
                version_id=state.challenger.version_id,
                template=state.challenger.template,
                is_challenger=False,
            )
            state.challenger = None

        self._publish_learning(
            LearningEvent(
                event_type=LearningEventType.PROMPT_VARIANT_PROMOTED,
                agent_id=agent_id,
                scope=PropagationScope.FLEET_WIDE,
                payload={
                    "tenant_id": tenant_id,
                    "previous_version": old_version,
                    "new_version": state.champion.version_id,
                },
            )
        )

    # -- read surface --------------------------------------------------

    def prompt_for(
        self,
        agent_id: str,
        *,
        tenant_id: str = "default",
    ) -> PromptSelection:
        key = (tenant_id, agent_id)
        with self._lock:
            state = self._prompts[key]
            # Return the challenger 10% of the time if one exists
            # (PR-1 simplification — real A/B split lands in PR-2).
            return state.challenger if state.challenger is not None else state.champion

    def leaderboard(
        self,
        *,
        dim: FitnessDimension = FitnessDimension.ACCURACY,
        tenant_id: str = "default",
        top: int = 20,
    ) -> list[AgentScore]:
        with self._lock:
            scores = []
            for (tid, aid), state in self._fitness.items():
                if tid != tenant_id:
                    continue
                value = state.dimension_average(dim)
                scores.append(
                    AgentScore(
                        agent_id=aid,
                        dimension=dim,
                        value=value,
                        sample_count=len(state.observations),
                        updated_at=self._clock(),
                    )
                )
        scores.sort(key=lambda s: s.value, reverse=True)
        return scores[:top]

    # -- promotion surface (RFC #246 PR-4) ------------------------------

    def _current_fitness(self, agent_name: str, *, tenant_id: str = "default") -> float | None:
        """Return the current composite fitness for an agent, or None if
        the agent has no recorded observations."""
        key = (tenant_id, agent_name)
        state = self._fitness.get(key)
        if state is None or not state.observations:
            return None
        return state.score(self._config)

    def promote_agent(
        self,
        agent_name: str,
        *,
        org_id: str = "default",
        reason: str = "",
    ) -> AgentStatusSnapshot:
        """Promote an agent to :attr:`AgentStatus.PROMOTED`.

        Raises :class:`KeyError` when the agent has no fitness records
        yet — promotion without any observed fitness is a bug in the
        caller, so we fail loudly instead of silently promoting a
        phantom agent.
        """
        with self._lock:
            fitness = self._current_fitness(agent_name)
            if fitness is None:
                raise KeyError(f"No fitness records for agent {agent_name!r}")
            snap = AgentStatusSnapshot(
                agent_name=agent_name,
                org_id=org_id,
                status=AgentStatus.PROMOTED,
                current_fitness=fitness,
                promoted_at=self._clock(),
                reason=reason,
            )
            self._statuses[(org_id, agent_name)] = snap

        try:
            self._publish_learning(
                LearningEvent(
                    event_type=LearningEventType.PROMPT_VARIANT_PROMOTED,
                    agent_id=agent_name,
                    scope=PropagationScope.FLEET_WIDE,
                    payload={
                        "org_id": org_id,
                        "fitness": fitness,
                        "reason": reason,
                        "manual": True,
                    },
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "evolution.promote_agent.publish_failed",
                agent_name=agent_name,
                org_id=org_id,
                error=str(exc),
            )
        return snap

    def demote_agent(
        self,
        agent_name: str,
        *,
        org_id: str = "default",
        reason: str = "",
        disable: bool = False,
    ) -> AgentStatusSnapshot:
        """Demote an agent, optionally disabling it outright.

        Symmetric to :meth:`promote_agent`. Raises :class:`KeyError`
        when the agent has no recorded fitness.
        """
        with self._lock:
            fitness = self._current_fitness(agent_name)
            if fitness is None:
                raise KeyError(f"No fitness records for agent {agent_name!r}")
            status = AgentStatus.DISABLED if disable else AgentStatus.DEMOTED
            snap = AgentStatusSnapshot(
                agent_name=agent_name,
                org_id=org_id,
                status=status,
                current_fitness=fitness,
                demoted_at=self._clock(),
                reason=reason,
            )
            self._statuses[(org_id, agent_name)] = snap

        try:
            self._publish_learning(
                LearningEvent(
                    event_type=LearningEventType.PROMPT_VARIANT_DEMOTED,
                    agent_id=agent_name,
                    scope=PropagationScope.FLEET_WIDE,
                    payload={
                        "org_id": org_id,
                        "fitness": fitness,
                        "reason": reason,
                        "disable": disable,
                        "manual": True,
                    },
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "evolution.demote_agent.publish_failed",
                agent_name=agent_name,
                org_id=org_id,
                error=str(exc),
            )
        return snap

    def rolling_window(
        self,
        agent_name: str,
        *,
        window_days: int = 7,
        tenant_id: str = "default",
    ) -> FitnessWindow:
        """Return a per-day rolling window of composite fitness.

        This is the canonical rolling-window read path for the promotion
        route and dashboards (RFC #246 PR-4 / PR-6).

        Unknown agents yield a zero-valued window rather than raising —
        read paths should be tolerant so dashboards don't crash on fresh
        tenants.
        """
        key = (tenant_id, agent_name)
        now = self._clock()
        cutoff = now - timedelta(days=window_days)

        with self._lock:
            state = self._fitness.get(key)
            if state is None or not state.observations:
                return FitnessWindow(
                    agent_name=agent_name,
                    window_days=window_days,
                )
            # Snapshot under the lock so concurrent writers can't mutate
            # the deques mid-iteration.
            paired: list[tuple[datetime, FitnessObservation]] = [
                (ts, obs)
                for ts, obs in zip(state.timestamps, state.observations, strict=False)
                if ts >= cutoff
            ]

        if not paired:
            return FitnessWindow(
                agent_name=agent_name,
                window_days=window_days,
            )

        # Bucket by UTC day.
        buckets: dict[int, list[FitnessObservation]] = defaultdict(list)
        day_seconds = 86400
        for ts, obs in paired:
            day_key = int(ts.timestamp() // day_seconds)
            buckets[day_key].append(obs)

        daily: list[DailyFitnessPoint] = []
        for day_key in sorted(buckets.keys()):
            obs_list = buckets[day_key]
            n = len(obs_list)
            dim_avgs: dict[str, float] = {}
            for dim in FitnessDimension:
                dim_avgs[dim.value] = sum(getattr(o, dim.value) for o in obs_list) / n
            composite = sum(o.score(self._config) for o in obs_list) / n
            daily.append(
                DailyFitnessPoint(
                    day_epoch=float(day_key * day_seconds),
                    composite=round(composite, 4),
                    dimensions={k: round(v, 4) for k, v in dim_avgs.items()},
                    sample_count=n,
                )
            )

        composites = [p.composite for p in daily]
        return FitnessWindow(
            agent_name=agent_name,
            window_days=window_days,
            composite_current=daily[-1].composite,
            composite_avg=round(sum(composites) / len(composites), 4),
            min_composite=min(composites),
            max_composite=max(composites),
            sample_count=len(paired),
            daily_points=daily,
        )

    def leaderboard_rows(
        self,
        *,
        org_id: str | None = None,
        top_n: int = 50,
        tenant_id: str = "default",
    ) -> list[dict[str, Any]]:
        """Return a promotion-style leaderboard of agents.

        Canonical leaderboard read path used by ``api/routes/agent_promotion.py``
        so callers never reach into store internals. Returns the union of
        agents that have recorded fitness and agents with an explicit
        status snapshot (RFC #246 PR-4 / PR-6).
        """
        with self._lock:
            # Union of agents that have fitness observations (for this tenant)
            # and agents that have an explicit status snapshot.
            fitness_agents: set[str] = {aid for (tid, aid) in self._fitness if tid == tenant_id}
            status_agents: set[tuple[str, str]] = set(self._statuses.keys())

            rows: list[dict[str, Any]] = []

            seen: set[tuple[str, str]] = set()
            # First, fitness-only agents default to org_id="default" unless
            # a status snapshot exists under a different org_id.
            for agent_name in fitness_agents:
                matching_orgs = [oid for (oid, aname) in status_agents if aname == agent_name]
                if not matching_orgs:
                    matching_orgs = ["default"]
                for oid in matching_orgs:
                    seen.add((oid, agent_name))
                    rows.append(
                        self._row_for(
                            agent_name=agent_name,
                            org_id=oid,
                            tenant_id=tenant_id,
                        )
                    )
            # Then, pure status-only rows (demoted/disabled agents with no
            # recent observations).
            for oid, aname in status_agents:
                if (oid, aname) in seen:
                    continue
                rows.append(
                    self._row_for(
                        agent_name=aname,
                        org_id=oid,
                        tenant_id=tenant_id,
                    )
                )

        if org_id is not None:
            rows = [r for r in rows if r["org_id"] == org_id]

        rows.sort(key=lambda r: r["composite_fitness"], reverse=True)
        trimmed = rows[:top_n]
        for idx, row in enumerate(trimmed, start=1):
            row["rank"] = idx
        return trimmed

    def _row_for(
        self,
        *,
        agent_name: str,
        org_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Build a single leaderboard row under the store lock's critical
        section. Must be called with ``self._lock`` held."""
        state = self._fitness.get((tenant_id, agent_name))
        if state is not None and state.observations:
            composite = state.score(self._config)
        else:
            composite = 0.0
        snap = self._statuses.get((org_id, agent_name))
        if snap is not None:
            status = snap.status.value
            promoted_at = snap.promoted_at.isoformat() if snap.promoted_at else None
            demoted_at = snap.demoted_at.isoformat() if snap.demoted_at else None
            if composite == 0.0 and snap.current_fitness:
                composite = snap.current_fitness
        else:
            status = AgentStatus.ACTIVE.value
            promoted_at = None
            demoted_at = None
        return {
            "agent_name": agent_name,
            "org_id": org_id,
            "status": status,
            "composite_fitness": composite,
            "promoted_at": promoted_at,
            "demoted_at": demoted_at,
        }
