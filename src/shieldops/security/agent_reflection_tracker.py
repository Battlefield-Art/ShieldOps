"""Agent Reflection Tracker — track agent self-reflection."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReflectionDepth(StrEnum):
    DEEP = "deep"
    STANDARD = "standard"
    SHALLOW = "shallow"


class ActionOutcome(StrEnum):
    EFFECTIVE = "effective"
    PARTIAL = "partial"
    INEFFECTIVE = "ineffective"
    COUNTERPRODUCTIVE = "counterproductive"


class LearningCategory(StrEnum):
    THRESHOLD_TUNE = "threshold_tune"
    RULE_UPDATE = "rule_update"
    PLAYBOOK_FIX = "playbook_fix"
    FP_SUPPRESS = "fp_suppress"


# --- Models ---


class ReflectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    depth: ReflectionDepth = ReflectionDepth.STANDARD
    outcome: ActionOutcome = ActionOutcome.PARTIAL
    category: LearningCategory = LearningCategory.THRESHOLD_TUNE
    action_taken: str = ""
    lesson_learned: str = ""
    confidence: float = 0.0
    mistake_repeated: bool = False
    created_at: float = Field(default_factory=time.time)


class ReflectionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    total_reflections: int = 0
    effective_rate: float = 0.0
    mistake_repeat_rate: float = 0.0
    dominant_category: str = ""
    improvement_trend: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class ReflectionReport(BaseModel):
    total_reflections: int = 0
    by_depth: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    effective_rate_pct: float = 0.0
    mistake_repeat_rate_pct: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentReflectionTrackerEngine:
    """Track agent self-reflection and learning."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[ReflectionRecord] = []
        logger.info(
            "agent_reflection_tracker.initialized",
            max_records=max_records,
        )

    # -- record / query --

    def add_record(
        self,
        agent_id: str,
        depth: ReflectionDepth = ReflectionDepth.STANDARD,
        outcome: ActionOutcome = ActionOutcome.PARTIAL,
        category: LearningCategory = (LearningCategory.THRESHOLD_TUNE),
        action_taken: str = "",
        lesson_learned: str = "",
        confidence: float = 0.5,
        mistake_repeated: bool = False,
    ) -> ReflectionRecord:
        record = ReflectionRecord(
            agent_id=agent_id,
            depth=depth,
            outcome=outcome,
            category=category,
            action_taken=action_taken,
            lesson_learned=lesson_learned,
            confidence=confidence,
            mistake_repeated=mistake_repeated,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_reflection_tracker.record_added",
            record_id=record.id,
            agent_id=agent_id,
            outcome=outcome.value,
        )
        return record

    def process(self, agent_id: str) -> ReflectionAnalysis:
        refs = [r for r in self._records if r.agent_id == agent_id]
        if not refs:
            return ReflectionAnalysis(agent_id=agent_id)
        effective = sum(1 for r in refs if r.outcome == ActionOutcome.EFFECTIVE)
        eff_rate = round(effective / len(refs) * 100, 2)
        repeats = sum(1 for r in refs if r.mistake_repeated)
        repeat_rate = round(repeats / len(refs) * 100, 2)
        cat_counts: dict[str, int] = {}
        for r in refs:
            key = r.category.value
            cat_counts[key] = cat_counts.get(key, 0) + 1
        dominant = (
            max(
                cat_counts,
                key=cat_counts.get,  # type: ignore[arg-type]
            )
            if cat_counts
            else ""
        )
        half = len(refs) // 2
        if half > 0:
            first_eff = sum(1 for r in refs[:half] if r.outcome == ActionOutcome.EFFECTIVE) / half
            second_eff = sum(1 for r in refs[half:] if r.outcome == ActionOutcome.EFFECTIVE) / max(
                len(refs) - half, 1
            )
            trend = round(second_eff - first_eff, 4)
        else:
            trend = 0.0
        return ReflectionAnalysis(
            agent_id=agent_id,
            total_reflections=len(refs),
            effective_rate=eff_rate,
            mistake_repeat_rate=repeat_rate,
            dominant_category=dominant,
            improvement_trend=trend,
        )

    def generate_report(self) -> ReflectionReport:
        by_depth: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for r in self._records:
            by_depth[r.depth.value] = by_depth.get(r.depth.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
            by_category[r.category.value] = by_category.get(r.category.value, 0) + 1
        total = len(self._records)
        effective = sum(1 for r in self._records if r.outcome == ActionOutcome.EFFECTIVE)
        eff_rate = round(effective / total * 100, 2) if total else 0.0
        repeats = sum(1 for r in self._records if r.mistake_repeated)
        rr = round(repeats / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if rr > 20:
            recs.append("High mistake repeat rate — review learning loops")
        counter = sum(1 for r in self._records if r.outcome == ActionOutcome.COUNTERPRODUCTIVE)
        if counter > 0:
            recs.append(f"{counter} counterproductive action(s) detected")
        if eff_rate < 50 and total > 0:
            recs.append("Low effectiveness — consider deeper reflection cycles")
        if not recs:
            recs.append("Reflection quality is healthy")
        return ReflectionReport(
            total_reflections=total,
            by_depth=by_depth,
            by_outcome=by_outcome,
            by_category=by_category,
            effective_rate_pct=eff_rate,
            mistake_repeat_rate_pct=rr,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        outcome_dist: dict[str, int] = {}
        for r in self._records:
            key = r.outcome.value
            outcome_dist[key] = outcome_dist.get(key, 0) + 1
        return {
            "total_reflections": len(self._records),
            "max_records": self._max_records,
            "outcome_distribution": outcome_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
            "mistake_repeats": sum(1 for r in self._records if r.mistake_repeated),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("agent_reflection_tracker.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def track_reflection(
        self,
        agent_id: str,
        action_taken: str,
        outcome: ActionOutcome,
        lesson_learned: str = "",
        depth: ReflectionDepth = (ReflectionDepth.STANDARD),
        category: LearningCategory = (LearningCategory.THRESHOLD_TUNE),
    ) -> dict[str, Any]:
        """Track a reflection event for an agent."""
        previous = [
            r
            for r in self._records
            if r.agent_id == agent_id
            and r.action_taken == action_taken
            and r.outcome != ActionOutcome.EFFECTIVE
        ]
        repeated = len(previous) > 0
        record = self.add_record(
            agent_id=agent_id,
            depth=depth,
            outcome=outcome,
            category=category,
            action_taken=action_taken,
            lesson_learned=lesson_learned,
            mistake_repeated=repeated,
        )
        return {
            "record_id": record.id,
            "agent_id": agent_id,
            "outcome": outcome.value,
            "mistake_repeated": repeated,
            "tracked": True,
        }

    def measure_improvement(
        self,
        agent_id: str,
        window_size: int = 20,
    ) -> dict[str, Any]:
        """Measure improvement trend for an agent."""
        refs = [r for r in self._records if r.agent_id == agent_id]
        if len(refs) < window_size:
            return {
                "agent_id": agent_id,
                "sufficient_data": False,
                "total_reflections": len(refs),
            }
        recent = refs[-window_size:]
        older = refs[-window_size * 2 : -window_size]
        if not older:
            older = refs[: len(refs) // 2]
        recent_eff = sum(1 for r in recent if r.outcome == ActionOutcome.EFFECTIVE) / len(recent)
        older_eff = (
            sum(1 for r in older if r.outcome == ActionOutcome.EFFECTIVE) / len(older)
            if older
            else 0.0
        )
        delta = round(recent_eff - older_eff, 4)
        return {
            "agent_id": agent_id,
            "sufficient_data": True,
            "recent_effectiveness": round(recent_eff * 100, 2),
            "older_effectiveness": round(older_eff * 100, 2),
            "improvement_delta": delta,
            "improving": delta > 0,
        }

    def identify_recurring_mistakes(
        self,
        agent_id: str | None = None,
        min_occurrences: int = 2,
    ) -> list[dict[str, Any]]:
        """Find repeated mistakes across reflections."""
        targets = self._records
        if agent_id:
            targets = [r for r in self._records if r.agent_id == agent_id]
        action_map: dict[str, list[ReflectionRecord]] = {}
        for r in targets:
            if r.outcome in (
                ActionOutcome.INEFFECTIVE,
                ActionOutcome.COUNTERPRODUCTIVE,
            ):
                action_map.setdefault(r.action_taken, []).append(r)
        results: list[dict[str, Any]] = []
        for action, recs in action_map.items():
            if len(recs) >= min_occurrences:
                results.append(
                    {
                        "action": action,
                        "occurrences": len(recs),
                        "agents_affected": list({r.agent_id for r in recs}),
                        "worst_outcome": max(r.outcome.value for r in recs),
                        "latest_at": max(r.created_at for r in recs),
                    }
                )
        results.sort(key=lambda x: x["occurrences"], reverse=True)
        logger.info(
            "agent_reflection_tracker.recurring_mistakes",
            count=len(results),
        )
        return results
