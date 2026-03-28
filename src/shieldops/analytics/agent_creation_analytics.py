"""Agent Creation Analytics — track creation and adoption."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CreationMetric(StrEnum):
    TIME_TO_CREATE = "time_to_create"
    LINES_OF_CODE = "lines_of_code"
    TEST_COVERAGE = "test_coverage"
    REVIEW_CYCLES = "review_cycles"


class QualityTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    UNKNOWN = "unknown"


class AdoptionRate(StrEnum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    NONE = "none"


# --- Models ---


class CreationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    metric: CreationMetric = CreationMetric.TIME_TO_CREATE
    quality: QualityTrend = QualityTrend.STABLE
    adoption: AdoptionRate = AdoptionRate.MODERATE
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CreationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    metric: CreationMetric = CreationMetric.TIME_TO_CREATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CreationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_adoption: dict[str, int] = Field(default_factory=dict)
    low_adoption: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentCreationAnalytics:
    """Track agent creation rates and adoption."""

    def __init__(
        self,
        max_records: int = 200000,
        quality_threshold: float = 70.0,
    ) -> None:
        self._max = max_records
        self._threshold = quality_threshold
        self._records: list[CreationRecord] = []
        self._analyses: list[CreationAnalysis] = []
        logger.info(
            "agent_creation_analytics.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_name: str = "",
        metric: CreationMetric = (CreationMetric.TIME_TO_CREATE),
        quality: QualityTrend = QualityTrend.STABLE,
        adoption: AdoptionRate = (AdoptionRate.MODERATE),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CreationRecord:
        rec = CreationRecord(
            agent_name=agent_name,
            metric=metric,
            quality=quality,
            adoption=adoption,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "agent_creation.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> CreationAnalysis:
        matches = [r for r in self._records if r.agent_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = CreationAnalysis(
            agent_name=key,
            analysis_score=round(avg, 2),
            threshold=self._threshold,
            breached=avg < self._threshold,
            description=(f"Analyzed {len(matches)} creations"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def track_creation_rate(
        self,
    ) -> dict[str, Any]:
        """Count agents created per time window."""
        if not self._records:
            return {"rate": 0.0, "total": 0}
        span = self._records[-1].created_at - self._records[0].created_at
        hours = max(span / 3600, 1.0)
        rate = len(self._records) / hours
        return {
            "rate_per_hour": round(rate, 4),
            "total": len(self._records),
        }

    def measure_quality_trend(
        self,
    ) -> dict[str, Any]:
        """Split-half trend on quality scores."""
        if len(self._records) < 2:
            return {"trend": "insufficient_data"}
        scores = [r.score for r in self._records]
        mid = len(scores) // 2
        first = sum(scores[:mid]) / mid
        second = sum(scores[mid:]) / len(scores[mid:])
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

    def analyze_adoption(
        self,
    ) -> dict[str, Any]:
        """Aggregate adoption rate distribution."""
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.adoption.value
            dist[k] = dist.get(k, 0) + 1
        low = dist.get(AdoptionRate.LOW.value, 0)
        none_count = dist.get(AdoptionRate.NONE.value, 0)
        return {
            "distribution": dist,
            "low_adoption_count": low + none_count,
            "total": len(self._records),
        }

    # -- report / stats ---

    def generate_report(self) -> CreationReport:
        by_metric: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        by_adoption: dict[str, int] = {}
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            q = r.quality.value
            by_quality[q] = by_quality.get(q, 0) + 1
            a = r.adoption.value
            by_adoption[a] = by_adoption.get(a, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        low = [
            r.agent_name
            for r in self._records
            if r.adoption in (AdoptionRate.LOW, AdoptionRate.NONE)
        ][:5]
        recs: list[str] = []
        if low:
            recs.append(f"{len(low)} agent(s) have low adoption")
        if not recs:
            recs.append("Agent adoption is healthy")
        return CreationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_metric=by_metric,
            by_quality=by_quality,
            by_adoption=by_adoption,
            low_adoption=low,
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
        logger.info("agent_creation_analytics.cleared")
        return {"status": "cleared"}
