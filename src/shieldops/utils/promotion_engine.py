"""Fitness-gated promotion engine.

Evaluates agents against composite fitness thresholds and promotes/demotes
them across the beta → ga → disabled lifecycle. Operates in-memory by default
so it can be used in tests without a live database, and exposes an async
hook that persists state changes when a SQLAlchemy session is available.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.db.models_agent_status import AgentLifecycleStatus
from shieldops.utils.fitness_aggregator import (
    FitnessAggregator,
    RollingFitnessWindow,
    get_fitness_aggregator,
)

logger = structlog.get_logger()


# Default criteria — promotion requires sustained excellence,
# demotion triggers quickly on degradation.
PROMOTION_THRESHOLD = 0.85
PROMOTION_CONSECUTIVE_DAYS = 7
DEMOTION_THRESHOLD = 0.70
DEMOTION_HOURS = 24


@dataclass
class AgentStatusSnapshot:
    """In-memory representation of an agent status row."""

    agent_name: str
    org_id: str
    status: AgentLifecycleStatus = AgentLifecycleStatus.BETA
    current_fitness: float = 0.0
    fitness_history: list[dict[str, Any]] = field(default_factory=list)
    promoted_at: datetime | None = None
    demoted_at: datetime | None = None
    last_evaluated_at: datetime | None = None


@dataclass
class EvaluationResult:
    """Outcome of a single evaluate_agent call."""

    agent_name: str
    org_id: str
    previous_status: AgentLifecycleStatus
    new_status: AgentLifecycleStatus
    composite_fitness: float
    action: str  # "promoted", "demoted", "none"
    reason: str = ""
    window: RollingFitnessWindow | None = None


class PromotionEngine:
    """Evaluates agents and drives fitness-gated promotion/demotion."""

    def __init__(
        self,
        aggregator: FitnessAggregator | None = None,
        *,
        promotion_threshold: float = PROMOTION_THRESHOLD,
        promotion_consecutive_days: int = PROMOTION_CONSECUTIVE_DAYS,
        demotion_threshold: float = DEMOTION_THRESHOLD,
        demotion_hours: float = DEMOTION_HOURS,
        history_limit: int = 30,
    ) -> None:
        self._aggregator = aggregator or get_fitness_aggregator()
        self.promotion_threshold = promotion_threshold
        self.promotion_consecutive_days = promotion_consecutive_days
        self.demotion_threshold = demotion_threshold
        self.demotion_hours = demotion_hours
        self.history_limit = history_limit
        # (agent_name, org_id) → snapshot
        self._status: dict[tuple[str, str], AgentStatusSnapshot] = {}
        # Append-only in-memory audit log for tests + fallback when no DB.
        self._audit_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_status(self, agent_name: str, org_id: str = "default") -> AgentStatusSnapshot:
        """Get (or lazily create) a status snapshot for an agent."""
        key = (agent_name, org_id)
        snap = self._status.get(key)
        if snap is None:
            snap = AgentStatusSnapshot(agent_name=agent_name, org_id=org_id)
            self._status[key] = snap
        return snap

    def list_statuses(self, org_id: str | None = None) -> list[AgentStatusSnapshot]:
        """Return all tracked status snapshots, optionally filtered by org."""
        if org_id is None:
            return list(self._status.values())
        return [s for s in self._status.values() if s.org_id == org_id]

    def evaluate_agent(
        self,
        agent_name: str,
        org_id: str = "default",
        *,
        now: float | None = None,
    ) -> EvaluationResult:
        """Evaluate an agent and auto-promote or auto-demote if warranted."""
        snap = self.get_status(agent_name, org_id)
        previous_status = snap.status
        window = self._aggregator.rolling_window(
            agent_name,
            window_days=max(self.promotion_consecutive_days, 7),
            now=now,
        )
        composite = window.composite_current or self._aggregator.composite_fitness(agent_name)
        snap.current_fitness = composite
        snap.last_evaluated_at = datetime.now(UTC)
        self._append_history(snap, composite, now=now)

        action = "none"
        reason = ""
        new_status = previous_status

        # Promotion: beta → ga after N consecutive days above threshold.
        if previous_status == AgentLifecycleStatus.BETA:
            consecutive = window.consecutive_days_above(self.promotion_threshold)
            if consecutive >= self.promotion_consecutive_days:
                new_status = AgentLifecycleStatus.GA
                action = "promoted"
                reason = f"composite>={self.promotion_threshold} for {consecutive} consecutive days"
                self._apply_promotion(snap, reason=reason)

        # Demotion: ga → beta after H hours below threshold.
        elif previous_status == AgentLifecycleStatus.GA:
            hours_below = window.consecutive_hours_below(self.demotion_threshold)
            if hours_below >= self.demotion_hours:
                new_status = AgentLifecycleStatus.BETA
                action = "demoted"
                reason = f"composite<{self.demotion_threshold} for {hours_below:.0f} hours"
                self._apply_demotion(snap, reason=reason)

        return EvaluationResult(
            agent_name=agent_name,
            org_id=org_id,
            previous_status=previous_status,
            new_status=new_status,
            composite_fitness=composite,
            action=action,
            reason=reason,
            window=window,
        )

    def promote_agent(
        self,
        agent_name: str,
        org_id: str = "default",
        *,
        reason: str = "manual promotion",
    ) -> AgentStatusSnapshot:
        """Manually promote an agent to GA."""
        snap = self.get_status(agent_name, org_id)
        self._apply_promotion(snap, reason=reason, manual=True)
        return snap

    def demote_agent(
        self,
        agent_name: str,
        org_id: str = "default",
        *,
        reason: str = "manual demotion",
        disable: bool = False,
    ) -> AgentStatusSnapshot:
        """Manually demote an agent back to beta (or disable it)."""
        snap = self.get_status(agent_name, org_id)
        self._apply_demotion(snap, reason=reason, manual=True, disable=disable)
        return snap

    def run_evaluation_cycle(
        self,
        agent_names: list[str] | None = None,
        org_id: str = "default",
    ) -> list[EvaluationResult]:
        """Evaluate all tracked agents (called hourly by scheduler)."""
        if agent_names is None:
            # Use all agents known to the aggregator's tracker plus any
            # agents that already have a status snapshot.
            tracker_agents = set(self._aggregator._tracker._profiles.keys())  # noqa: SLF001
            status_agents = {name for (name, _) in self._status}
            agent_names = sorted(tracker_agents | status_agents)
        results: list[EvaluationResult] = []
        for name in agent_names:
            try:
                results.append(self.evaluate_agent(name, org_id))
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "promotion.evaluate_failed",
                    agent_name=name,
                    org_id=org_id,
                    error=str(exc),
                )
        logger.info(
            "promotion.cycle_complete",
            org_id=org_id,
            evaluated=len(results),
            promoted=sum(1 for r in results if r.action == "promoted"),
            demoted=sum(1 for r in results if r.action == "demoted"),
        )
        return results

    def leaderboard(
        self,
        org_id: str | None = None,
        top_n: int = 50,
    ) -> list[dict[str, Any]]:
        """Return agents sorted by composite fitness."""
        snaps = self.list_statuses(org_id)
        # Ensure every snapshot reflects the latest composite from the aggregator.
        enriched: list[dict[str, Any]] = []
        for snap in snaps:
            composite = self._aggregator.composite_fitness(snap.agent_name)
            if composite > 0.0:
                snap.current_fitness = composite
            enriched.append(
                {
                    "agent_name": snap.agent_name,
                    "org_id": snap.org_id,
                    "status": snap.status.value,
                    "composite_fitness": snap.current_fitness,
                    "promoted_at": snap.promoted_at.isoformat() if snap.promoted_at else None,
                    "demoted_at": snap.demoted_at.isoformat() if snap.demoted_at else None,
                }
            )
        enriched.sort(key=lambda row: row["composite_fitness"], reverse=True)
        for idx, row in enumerate(enriched[:top_n], start=1):
            row["rank"] = idx
        return enriched[:top_n]

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Read-only view of the in-memory audit log."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_promotion(
        self,
        snap: AgentStatusSnapshot,
        *,
        reason: str,
        manual: bool = False,
    ) -> None:
        snap.status = AgentLifecycleStatus.GA
        snap.promoted_at = datetime.now(UTC)
        self._record_audit(snap, action="promoted", reason=reason, manual=manual)
        self._notify_status_change(snap, "promoted", reason)

    def _apply_demotion(
        self,
        snap: AgentStatusSnapshot,
        *,
        reason: str,
        manual: bool = False,
        disable: bool = False,
    ) -> None:
        snap.status = AgentLifecycleStatus.DISABLED if disable else AgentLifecycleStatus.BETA
        snap.demoted_at = datetime.now(UTC)
        self._record_audit(snap, action="demoted", reason=reason, manual=manual)
        self._notify_status_change(snap, "demoted", reason)

    def _append_history(
        self,
        snap: AgentStatusSnapshot,
        composite: float,
        *,
        now: float | None,
    ) -> None:
        ts = now if now is not None else time.time()
        snap.fitness_history.append(
            {
                "timestamp": ts,
                "composite": round(composite, 4),
                "status": snap.status.value,
            }
        )
        if len(snap.fitness_history) > self.history_limit:
            snap.fitness_history = snap.fitness_history[-self.history_limit :]

    def _record_audit(
        self,
        snap: AgentStatusSnapshot,
        *,
        action: str,
        reason: str,
        manual: bool,
    ) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_name": snap.agent_name,
            "org_id": snap.org_id,
            "action": action,
            "reason": reason,
            "manual": manual,
            "composite_fitness": snap.current_fitness,
            "new_status": snap.status.value,
        }
        self._audit_log.append(entry)
        logger.info("promotion.audit", **entry)

    def _notify_status_change(
        self,
        snap: AgentStatusSnapshot,
        action: str,
        reason: str,
    ) -> None:
        # Placeholder for Slack/email/PagerDuty notification fan-out.
        logger.info(
            "promotion.notify",
            channel="placeholder",
            agent_name=snap.agent_name,
            org_id=snap.org_id,
            action=action,
            reason=reason,
            composite_fitness=snap.current_fitness,
            new_status=snap.status.value,
        )


# Module-level singleton
_engine: PromotionEngine | None = None


def get_promotion_engine() -> PromotionEngine:
    """Get or create the global promotion engine."""
    global _engine
    if _engine is None:
        _engine = PromotionEngine()
    return _engine


def reset_promotion_engine() -> None:
    """Reset the module-level singleton (for tests)."""
    global _engine
    _engine = None
