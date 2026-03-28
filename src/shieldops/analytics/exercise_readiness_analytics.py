"""Exercise Readiness Analytics — measure team readiness from exercises."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReadinessMetric(StrEnum):
    DETECTION_TIME = "detection_time"
    RESPONSE_TIME = "response_time"
    COORDINATION = "coordination"
    COMMUNICATION = "communication"
    RECOVERY = "recovery"


class TeamPerformance(StrEnum):
    EXCEPTIONAL = "exceptional"
    PROFICIENT = "proficient"
    DEVELOPING = "developing"
    NEEDS_IMPROVEMENT = "needs_improvement"
    UNTESTED = "untested"


class ImprovementRate(StrEnum):
    RAPID = "rapid"
    STEADY = "steady"
    FLAT = "flat"
    DECLINING = "declining"
    UNKNOWN = "unknown"


# --- Models ---


class ReadinessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_id: str = ""
    metric: ReadinessMetric = ReadinessMetric.DETECTION_TIME
    performance: TeamPerformance = TeamPerformance.DEVELOPING
    improvement: ImprovementRate = ImprovementRate.STEADY
    score: float = 0.0
    target_score: float = 0.0
    team_name: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ReadinessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_id: str = ""
    metric: ReadinessMetric = ReadinessMetric.DETECTION_TIME
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ReadinessReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_performance: dict[str, int] = Field(default_factory=dict)
    by_improvement: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExerciseReadinessAnalyticsEngine:
    """Measure team readiness from exercises."""

    def __init__(
        self,
        max_records: int = 200000,
        readiness_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = readiness_threshold
        self._records: list[ReadinessRecord] = []
        self._analyses: list[ReadinessAnalysis] = []
        logger.info(
            "exercise_readiness.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        exercise_id: str,
        metric: ReadinessMetric = (ReadinessMetric.DETECTION_TIME),
        performance: TeamPerformance = (TeamPerformance.DEVELOPING),
        improvement: ImprovementRate = (ImprovementRate.STEADY),
        score: float = 0.0,
        target_score: float = 0.0,
        team_name: str = "",
        service: str = "",
        team: str = "",
    ) -> ReadinessRecord:
        record = ReadinessRecord(
            exercise_id=exercise_id,
            metric=metric,
            performance=performance,
            improvement=improvement,
            score=score,
            target_score=target_score,
            team_name=team_name,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "exercise_readiness.record_added",
            record_id=record.id,
            exercise_id=exercise_id,
        )
        return record

    def get_record(self, record_id: str) -> ReadinessRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        metric: ReadinessMetric | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ReadinessRecord]:
        results = list(self._records)
        if metric is not None:
            results = [r for r in results if r.metric == metric]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations ---

    def measure_team_readiness(
        self,
    ) -> list[dict[str, Any]]:
        """Measure readiness per team."""
        team_data: dict[str, list[ReadinessRecord]] = {}
        for r in self._records:
            team_data.setdefault(r.team_name or "unknown", []).append(r)
        results: list[dict[str, Any]] = []
        for t, records in team_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            results.append(
                {
                    "team": t,
                    "count": len(records),
                    "avg_score": avg,
                    "ready": avg >= self._threshold,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_score"],
        )

    def track_improvement(
        self,
    ) -> list[dict[str, Any]]:
        """Track improvement rates."""
        imp_data: dict[str, list[ReadinessRecord]] = {}
        for r in self._records:
            imp_data.setdefault(r.improvement.value, []).append(r)
        results: list[dict[str, Any]] = []
        for imp, records in imp_data.items():
            results.append(
                {
                    "improvement_rate": imp,
                    "count": len(records),
                    "pct": round(
                        len(records) / max(len(self._records), 1) * 100,
                        2,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    def forecast_readiness(
        self,
    ) -> list[dict[str, Any]]:
        """Forecast readiness by metric trend."""
        metric_data: dict[str, list[ReadinessRecord]] = {}
        for r in self._records:
            metric_data.setdefault(r.metric.value, []).append(r)
        results: list[dict[str, Any]] = []
        for m, records in metric_data.items():
            sorted_r = sorted(records, key=lambda x: x.created_at)
            if len(sorted_r) < 2:
                continue
            mid = len(sorted_r) // 2
            early = sorted_r[:mid]
            recent = sorted_r[mid:]
            avg_e = round(
                sum(r.score for r in early) / len(early),
                2,
            )
            avg_r = round(
                sum(r.score for r in recent) / len(recent),
                2,
            )
            delta = round(avg_r - avg_e, 2)
            results.append(
                {
                    "metric": m,
                    "early_avg": avg_e,
                    "recent_avg": avg_r,
                    "delta": delta,
                    "trend": "improving" if delta > 2 else "stable" if delta > -2 else "declining",
                }
            )
        return sorted(
            results,
            key=lambda x: x["delta"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.exercise_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(self) -> ReadinessReport:
        by_m: dict[str, int] = {}
        by_p: dict[str, int] = {}
        by_i: dict[str, int] = {}
        for r in self._records:
            by_m[r.metric.value] = by_m.get(r.metric.value, 0) + 1
            by_p[r.performance.value] = by_p.get(r.performance.value, 0) + 1
            by_i[r.improvement.value] = by_i.get(r.improvement.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        recs: list[str] = []
        if avg < self._threshold:
            recs.append(f"Readiness {avg} below {self._threshold}")
        if not recs:
            recs.append("Exercise Readiness is healthy")
        return ReadinessReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_metric=by_m,
            by_performance=by_p,
            by_improvement=by_i,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("exercise_readiness.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        m_dist: dict[str, int] = {}
        for r in self._records:
            k = r.metric.value
            m_dist[k] = m_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "readiness_threshold": self._threshold,
            "metric_distribution": m_dist,
            "unique_exercises": len({r.exercise_id for r in self._records}),
        }
