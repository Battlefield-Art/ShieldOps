"""APT Exercise Analytics — measure defense effectiveness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExerciseMetric(StrEnum):
    DETECTION_RATE = "detection_rate"
    RESPONSE_TIME = "response_time"
    CONTAINMENT_SPEED = "containment_speed"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    COVERAGE = "coverage"


class DefenseEffectiveness(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    FAILING = "failing"


class AttackSuccess(StrEnum):
    BLOCKED = "blocked"
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    EVADED = "evaded"
    UNKNOWN = "unknown"


# --- Models ---


class ExerciseRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_name: str = ""
    metric: ExerciseMetric = ExerciseMetric.DETECTION_RATE
    effectiveness: DefenseEffectiveness = DefenseEffectiveness.GOOD
    attack_result: AttackSuccess = AttackSuccess.BLOCKED
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExerciseAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_name: str = ""
    metric: ExerciseMetric = ExerciseMetric.DETECTION_RATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExerciseReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_effectiveness: dict[str, int] = Field(default_factory=dict)
    by_attack_result: dict[str, int] = Field(default_factory=dict)
    poor_defenses: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class APTExerciseAnalytics:
    """Measure APT exercise and defense effectiveness."""

    def __init__(
        self,
        max_records: int = 200000,
        effectiveness_threshold: float = 70.0,
    ) -> None:
        self._max = max_records
        self._threshold = effectiveness_threshold
        self._records: list[ExerciseRecord] = []
        self._analyses: list[ExerciseAnalysis] = []
        logger.info(
            "apt_exercise_analytics.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        exercise_name: str = "",
        metric: ExerciseMetric = (ExerciseMetric.DETECTION_RATE),
        effectiveness: DefenseEffectiveness = (DefenseEffectiveness.GOOD),
        attack_result: AttackSuccess = (AttackSuccess.BLOCKED),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ExerciseRecord:
        rec = ExerciseRecord(
            exercise_name=exercise_name,
            metric=metric,
            effectiveness=effectiveness,
            attack_result=attack_result,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "apt_exercise_analytics.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> ExerciseAnalysis:
        matches = [r for r in self._records if r.exercise_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = ExerciseAnalysis(
            exercise_name=key,
            analysis_score=round(avg, 2),
            threshold=self._threshold,
            breached=avg < self._threshold,
            description=(f"Analyzed {len(matches)} exercises"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def measure_effectiveness(
        self,
    ) -> dict[str, Any]:
        """Aggregate defense effectiveness."""
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.effectiveness.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "distribution": dist,
            "total": len(self._records),
        }

    def track_exercise_history(
        self,
    ) -> list[dict[str, Any]]:
        """Group by exercise, return avg scores."""
        buckets: dict[str, list[float]] = {}
        for r in self._records:
            buckets.setdefault(r.exercise_name, []).append(r.score)
        results: list[dict[str, Any]] = []
        for name, scores in buckets.items():
            avg = sum(scores) / len(scores)
            results.append(
                {
                    "exercise": name,
                    "count": len(scores),
                    "avg_score": round(avg, 2),
                }
            )
        return results

    def benchmark_defense(
        self,
    ) -> dict[str, Any]:
        """Split-half trend analysis."""
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data"}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first = sum(vals[:mid]) / mid
        second = sum(vals[mid:]) / len(vals[mid:])
        delta = round(second - first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "first_avg": round(first, 2),
            "second_avg": round(second, 2),
        }

    # -- report / stats ---

    def generate_report(self) -> ExerciseReport:
        by_metric: dict[str, int] = {}
        by_eff: dict[str, int] = {}
        by_attack: dict[str, int] = {}
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            e = r.effectiveness.value
            by_eff[e] = by_eff.get(e, 0) + 1
            a = r.attack_result.value
            by_attack[a] = by_attack.get(a, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        poor = [
            r.exercise_name
            for r in self._records
            if r.effectiveness
            in (
                DefenseEffectiveness.POOR,
                DefenseEffectiveness.FAILING,
            )
        ][:5]
        recs: list[str] = []
        if poor:
            recs.append(f"{len(poor)} exercise(s) show poor defense")
        if not recs:
            recs.append("Defense effectiveness OK")
        return ExerciseReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_metric=by_metric,
            by_effectiveness=by_eff,
            by_attack_result=by_attack,
            poor_defenses=poor,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.metric.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "metric_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("apt_exercise_analytics.cleared")
        return {"status": "cleared"}
