"""Agent Fitness Tracker — multi-dimensional fitness scoring with rolling windows.

Tracks agent performance across 5 dimensions: accuracy, speed, cost, safety,
learning_rate. Enables fitness-based evolution decisions with decay for stale agents
and a leaderboard across the fleet.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.evolution.types import EvolutionReadiness, FitnessDimension, FitnessTrend

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FitnessObservation(BaseModel):
    """A single fitness measurement for one dimension."""

    dimension: FitnessDimension
    value: float = Field(ge=0.0, le=1.0)
    timestamp: float = Field(default_factory=time.time)
    context: dict[str, Any] = Field(default_factory=dict)


class DimensionScore(BaseModel):
    """Aggregated score for a single fitness dimension."""

    dimension: FitnessDimension
    current: float = 0.0
    rolling_avg: float = 0.0
    trend: FitnessTrend = FitnessTrend.INSUFFICIENT_DATA
    observation_count: int = 0
    last_updated: float = 0.0


class AgentFitness(BaseModel):
    """Complete fitness profile for an agent."""

    agent_id: str
    agent_type: str = ""
    composite_score: float = 0.0
    dimensions: dict[str, DimensionScore] = Field(default_factory=dict)
    generation: int = 0
    evolution_readiness: EvolutionReadiness = EvolutionReadiness.NEEDS_DATA
    last_evolution: float = 0.0
    total_observations: int = 0
    created_at: float = Field(default_factory=time.time)


class LeaderboardEntry(BaseModel):
    """An entry in the agent fitness leaderboard."""

    rank: int = 0
    agent_id: str = ""
    agent_type: str = ""
    composite_score: float = 0.0
    strongest: str = ""
    weakest: str = ""
    trend: FitnessTrend = FitnessTrend.INSUFFICIENT_DATA
    generation: int = 0


# ---------------------------------------------------------------------------
# Fitness Tracker
# ---------------------------------------------------------------------------

# Default weights for composite scoring
DEFAULT_WEIGHTS: dict[FitnessDimension, float] = {
    FitnessDimension.ACCURACY: 0.30,
    FitnessDimension.SPEED: 0.15,
    FitnessDimension.COST: 0.10,
    FitnessDimension.SAFETY: 0.30,
    FitnessDimension.LEARNING_RATE: 0.15,
}

# Minimum observations before scoring is meaningful
MIN_OBSERVATIONS = 5

# Rolling window size (number of observations to keep per dimension)
ROLLING_WINDOW = 50

# Fitness decay rate per hour of inactivity (up to 24h then plateau)
DECAY_RATE_PER_HOUR = 0.002


class FitnessTracker:
    """Multi-dimensional fitness tracking for the agent fleet.

    Records observations per agent per dimension, computes rolling averages,
    detects trends, and produces a leaderboard for evolution decisions.
    """

    def __init__(
        self,
        weights: dict[FitnessDimension, float] | None = None,
        rolling_window: int = ROLLING_WINDOW,
    ) -> None:
        self._weights = weights or dict(DEFAULT_WEIGHTS)
        self._window = rolling_window
        # agent_id → dimension → list[FitnessObservation]
        self._observations: dict[str, dict[str, list[FitnessObservation]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # agent_id → AgentFitness
        self._profiles: dict[str, AgentFitness] = {}
        # agent_id → generation counter
        self._generations: dict[str, int] = defaultdict(int)

    # ----- Recording -----

    def record(
        self,
        agent_id: str,
        dimension: FitnessDimension,
        value: float,
        agent_type: str = "",
        context: dict[str, Any] | None = None,
    ) -> FitnessObservation:
        """Record a fitness observation for an agent."""
        obs = FitnessObservation(
            dimension=dimension,
            value=max(0.0, min(1.0, value)),
            context=context or {},
        )
        bucket = self._observations[agent_id][dimension]
        bucket.append(obs)
        # Trim to rolling window
        if len(bucket) > self._window:
            self._observations[agent_id][dimension] = bucket[-self._window :]

        # Ensure profile exists
        if agent_id not in self._profiles:
            self._profiles[agent_id] = AgentFitness(
                agent_id=agent_id,
                agent_type=agent_type,
            )
        elif agent_type:
            self._profiles[agent_id].agent_type = agent_type

        self._recompute(agent_id)
        logger.debug(
            "fitness.recorded",
            agent_id=agent_id,
            dimension=dimension,
            value=round(value, 4),
        )
        return obs

    def record_batch(
        self,
        agent_id: str,
        observations: dict[FitnessDimension, float],
        agent_type: str = "",
    ) -> list[FitnessObservation]:
        """Record multiple dimension values at once."""
        return [
            self.record(agent_id, dim, val, agent_type=agent_type)
            for dim, val in observations.items()
        ]

    # ----- Querying -----

    def get_fitness(self, agent_id: str) -> AgentFitness:
        """Get the current fitness profile for an agent."""
        if agent_id not in self._profiles:
            return AgentFitness(agent_id=agent_id)
        return self._profiles[agent_id]

    def get_dimension(self, agent_id: str, dimension: FitnessDimension) -> DimensionScore:
        """Get score for a specific dimension."""
        profile = self.get_fitness(agent_id)
        return profile.dimensions.get(dimension, DimensionScore(dimension=dimension))

    def get_leaderboard(
        self,
        top_n: int = 20,
        dimension: FitnessDimension | None = None,
    ) -> list[LeaderboardEntry]:
        """Get the agent fitness leaderboard.

        If dimension is specified, rank by that dimension only.
        Otherwise rank by composite score.
        """
        entries: list[LeaderboardEntry] = []
        for agent_id, profile in self._profiles.items():
            if profile.total_observations < MIN_OBSERVATIONS:
                continue

            if dimension:
                dim_score = profile.dimensions.get(dimension)
                score = dim_score.rolling_avg if dim_score else 0.0
            else:
                score = profile.composite_score

            # Find strongest and weakest dimensions
            dims = profile.dimensions
            strongest = max(dims, key=lambda d: dims[d].rolling_avg) if dims else ""
            weakest = min(dims, key=lambda d: dims[d].rolling_avg) if dims else ""

            # Overall trend: majority vote
            trends = [d.trend for d in dims.values() if d.trend != FitnessTrend.INSUFFICIENT_DATA]
            if not trends:
                overall_trend = FitnessTrend.INSUFFICIENT_DATA
            else:
                improving = sum(1 for t in trends if t == FitnessTrend.IMPROVING)
                declining = sum(1 for t in trends if t == FitnessTrend.DECLINING)
                if improving > declining:
                    overall_trend = FitnessTrend.IMPROVING
                elif declining > improving:
                    overall_trend = FitnessTrend.DECLINING
                else:
                    overall_trend = FitnessTrend.STABLE

            entries.append(
                LeaderboardEntry(
                    agent_id=agent_id,
                    agent_type=profile.agent_type,
                    composite_score=round(score, 4),
                    strongest=strongest,
                    weakest=weakest,
                    trend=overall_trend,
                    generation=profile.generation,
                )
            )

        entries.sort(key=lambda e: e.composite_score, reverse=True)
        for i, entry in enumerate(entries):
            entry.rank = i + 1

        return entries[:top_n]

    def get_evolution_candidates(
        self,
        min_observations: int = MIN_OBSERVATIONS,
    ) -> list[str]:
        """Return agent IDs that are ready for evolution.

        An agent is ready if it has enough data and is either declining
        or has been stable long enough to attempt improvement.
        """
        candidates = []
        for agent_id, profile in self._profiles.items():
            if profile.total_observations < min_observations:
                continue
            if profile.evolution_readiness in (
                EvolutionReadiness.READY,
                EvolutionReadiness.DECLINING,
            ):
                candidates.append(agent_id)
        return candidates

    def mark_evolved(self, agent_id: str) -> int:
        """Mark an agent as having undergone evolution. Returns new generation."""
        self._generations[agent_id] += 1
        gen = self._generations[agent_id]
        if agent_id in self._profiles:
            self._profiles[agent_id].generation = gen
            self._profiles[agent_id].last_evolution = time.time()
            self._profiles[agent_id].evolution_readiness = EvolutionReadiness.THRIVING
        logger.info("fitness.evolved", agent_id=agent_id, generation=gen)
        return gen

    # ----- Stats -----

    def get_stats(self) -> dict[str, Any]:
        """Fleet-wide fitness statistics."""
        profiles = list(self._profiles.values())
        if not profiles:
            return {"total_agents": 0, "avg_composite": 0.0, "evolution_candidates": 0}

        scored = [p for p in profiles if p.total_observations >= MIN_OBSERVATIONS]
        return {
            "total_agents_tracked": len(profiles),
            "agents_with_sufficient_data": len(scored),
            "avg_composite": round(sum(p.composite_score for p in scored) / max(len(scored), 1), 4),
            "evolution_candidates": len(self.get_evolution_candidates()),
            "total_observations": sum(p.total_observations for p in profiles),
            "dimension_averages": {
                dim: round(
                    sum(p.dimensions[dim].rolling_avg for p in scored if dim in p.dimensions)
                    / max(sum(1 for p in scored if dim in p.dimensions), 1),
                    4,
                )
                for dim in FitnessDimension
            },
        }

    def clear_agent(self, agent_id: str) -> None:
        """Remove all tracking data for an agent."""
        self._observations.pop(agent_id, None)
        self._profiles.pop(agent_id, None)
        self._generations.pop(agent_id, None)

    # ----- Internal -----

    def _recompute(self, agent_id: str) -> None:
        """Recompute fitness scores for an agent from raw observations."""
        profile = self._profiles[agent_id]
        agent_obs = self._observations[agent_id]
        total_obs = sum(len(v) for v in agent_obs.values())
        profile.total_observations = total_obs

        dims: dict[str, DimensionScore] = {}
        for dim in FitnessDimension:
            obs_list = agent_obs.get(dim, [])
            if not obs_list:
                continue

            values = [o.value for o in obs_list]
            current = values[-1]
            rolling_avg = sum(values) / len(values)

            # Trend detection: compare first half avg to second half avg
            trend = FitnessTrend.INSUFFICIENT_DATA
            if len(values) >= 6:
                mid = len(values) // 2
                first_half = sum(values[:mid]) / mid
                second_half = sum(values[mid:]) / (len(values) - mid)
                delta = second_half - first_half
                if delta > 0.03:
                    trend = FitnessTrend.IMPROVING
                elif delta < -0.03:
                    trend = FitnessTrend.DECLINING
                else:
                    trend = FitnessTrend.STABLE

            dims[dim] = DimensionScore(
                dimension=dim,
                current=round(current, 4),
                rolling_avg=round(rolling_avg, 4),
                trend=trend,
                observation_count=len(obs_list),
                last_updated=obs_list[-1].timestamp,
            )

        profile.dimensions = dims

        # Composite score (weighted average with decay)
        if dims:
            weighted_sum = 0.0
            weight_total = 0.0
            for dim_key, ds in dims.items():
                w = self._weights.get(FitnessDimension(dim_key), 0.1)
                # Apply decay for stale dimensions
                age_hours = (time.time() - ds.last_updated) / 3600
                decay = max(0.0, 1.0 - min(age_hours, 24) * DECAY_RATE_PER_HOUR)
                weighted_sum += ds.rolling_avg * w * decay
                weight_total += w
            profile.composite_score = round(weighted_sum / max(weight_total, 0.01), 4)
        else:
            profile.composite_score = 0.0

        # Evolution readiness
        if total_obs < MIN_OBSERVATIONS:
            profile.evolution_readiness = EvolutionReadiness.NEEDS_DATA
        else:
            declining_count = sum(1 for d in dims.values() if d.trend == FitnessTrend.DECLINING)
            improving_count = sum(1 for d in dims.values() if d.trend == FitnessTrend.IMPROVING)
            if declining_count >= 2:
                profile.evolution_readiness = EvolutionReadiness.DECLINING
            elif improving_count >= 3:
                profile.evolution_readiness = EvolutionReadiness.THRIVING
            else:
                profile.evolution_readiness = EvolutionReadiness.READY

        profile.generation = self._generations.get(agent_id, 0)


# Module-level singleton
_tracker: FitnessTracker | None = None


def get_fitness_tracker() -> FitnessTracker:
    """Get or create the global fitness tracker."""
    global _tracker
    if _tracker is None:
        _tracker = FitnessTracker()
    return _tracker
