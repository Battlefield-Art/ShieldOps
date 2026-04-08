"""Fitness aggregator — composite fitness from 5 dimensions with rolling windows.

Consumes dimension scores from :mod:`shieldops.utils.fitness_tracker` and
produces composite fitness values suitable for the promotion engine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import structlog

from shieldops.utils.evolution.types import FitnessDimension
from shieldops.utils.fitness_tracker import FitnessTracker, get_fitness_tracker

logger = structlog.get_logger()


# Composite weights — matches docs/PRD and fitness_tracker defaults
COMPOSITE_WEIGHTS: dict[FitnessDimension, float] = {
    FitnessDimension.ACCURACY: 0.30,
    FitnessDimension.SAFETY: 0.30,
    FitnessDimension.SPEED: 0.15,
    FitnessDimension.LEARNING_RATE: 0.15,
    FitnessDimension.COST: 0.10,
}

SEVEN_DAYS_SECONDS = 7 * 24 * 3600
ONE_DAY_SECONDS = 24 * 3600


@dataclass
class DailyFitnessPoint:
    """Composite fitness score for a single day."""

    day_epoch: float
    composite: float
    dimensions: dict[str, float] = field(default_factory=dict)
    sample_count: int = 0


@dataclass
class RollingFitnessWindow:
    """Rolling fitness window result."""

    agent_name: str
    window_days: int
    composite_current: float
    composite_avg: float
    min_composite: float
    max_composite: float
    daily_points: list[DailyFitnessPoint] = field(default_factory=list)
    sample_count: int = 0

    def days_above(self, threshold: float) -> int:
        """Number of daily points at or above a threshold."""
        return sum(1 for p in self.daily_points if p.composite >= threshold)

    def days_below(self, threshold: float) -> int:
        """Number of daily points strictly below a threshold."""
        return sum(1 for p in self.daily_points if p.composite < threshold)

    def consecutive_days_above(self, threshold: float) -> int:
        """Longest run of trailing consecutive days at/above a threshold."""
        run = 0
        for point in reversed(self.daily_points):
            if point.composite >= threshold:
                run += 1
            else:
                break
        return run

    def consecutive_hours_below(self, threshold: float) -> float:
        """Hours from the most recent point backwards that remain below threshold."""
        if not self.daily_points:
            return 0.0
        hours = 0.0
        for point in reversed(self.daily_points):
            if point.composite < threshold:
                hours += 24.0
            else:
                break
        return hours


class FitnessAggregator:
    """Aggregates raw fitness observations into composite scores and windows."""

    def __init__(
        self,
        tracker: FitnessTracker | None = None,
        weights: dict[FitnessDimension, float] | None = None,
    ) -> None:
        self._tracker = tracker or get_fitness_tracker()
        self._weights = weights or dict(COMPOSITE_WEIGHTS)

    def composite_fitness(self, agent_name: str) -> float:
        """Current composite fitness for an agent (weighted rolling_avg)."""
        profile = self._tracker.get_fitness(agent_name)
        if not profile.dimensions:
            return 0.0
        weighted = 0.0
        total_weight = 0.0
        for dim_key, dim_score in profile.dimensions.items():
            weight = self._weights.get(FitnessDimension(dim_key), 0.0)
            if weight <= 0.0:
                continue
            weighted += dim_score.rolling_avg * weight
            total_weight += weight
        if total_weight <= 0.0:
            return 0.0
        return round(weighted / total_weight, 4)

    def rolling_window(
        self,
        agent_name: str,
        window_days: int = 7,
        *,
        now: float | None = None,
    ) -> RollingFitnessWindow:
        """Build a per-day rolling window of composite fitness for an agent."""
        now_ts = now if now is not None else time.time()
        window_start = now_ts - window_days * ONE_DAY_SECONDS

        # Gather all observations for this agent grouped by day.
        raw = self._tracker._observations.get(agent_name, {})  # noqa: SLF001
        buckets: dict[int, dict[str, list[float]]] = {}
        total_samples = 0
        for dim_key, obs_list in raw.items():
            for obs in obs_list:
                if obs.timestamp < window_start:
                    continue
                day_key = int(obs.timestamp // ONE_DAY_SECONDS)
                dim_map = buckets.setdefault(day_key, {})
                dim_map.setdefault(str(dim_key), []).append(obs.value)
                total_samples += 1

        daily: list[DailyFitnessPoint] = []
        for day_key in sorted(buckets.keys()):
            dim_avgs: dict[str, float] = {}
            for dim_name, values in buckets[day_key].items():
                dim_avgs[dim_name] = sum(values) / len(values)
            composite = self._compute_composite(dim_avgs)
            samples = sum(len(v) for v in buckets[day_key].values())
            daily.append(
                DailyFitnessPoint(
                    day_epoch=float(day_key * ONE_DAY_SECONDS),
                    composite=round(composite, 4),
                    dimensions={k: round(v, 4) for k, v in dim_avgs.items()},
                    sample_count=samples,
                )
            )

        composite_current = daily[-1].composite if daily else 0.0
        if daily:
            avg = sum(p.composite for p in daily) / len(daily)
            min_c = min(p.composite for p in daily)
            max_c = max(p.composite for p in daily)
        else:
            avg = min_c = max_c = 0.0

        return RollingFitnessWindow(
            agent_name=agent_name,
            window_days=window_days,
            composite_current=composite_current,
            composite_avg=round(avg, 4),
            min_composite=round(min_c, 4),
            max_composite=round(max_c, 4),
            daily_points=daily,
            sample_count=total_samples,
        )

    def _compute_composite(self, dim_avgs: dict[str, float]) -> float:
        """Weighted composite from per-dimension averages."""
        weighted = 0.0
        total_weight = 0.0
        for dim in FitnessDimension:
            weight = self._weights.get(dim, 0.0)
            if weight <= 0.0 or dim.value not in dim_avgs:
                continue
            weighted += dim_avgs[dim.value] * weight
            total_weight += weight
        if total_weight <= 0.0:
            return 0.0
        return weighted / total_weight


# Module-level singleton
_aggregator: FitnessAggregator | None = None


def get_fitness_aggregator() -> FitnessAggregator:
    """Get or create the global fitness aggregator."""
    global _aggregator
    if _aggregator is None:
        _aggregator = FitnessAggregator()
    return _aggregator
