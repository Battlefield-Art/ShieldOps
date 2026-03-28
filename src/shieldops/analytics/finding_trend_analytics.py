"""FindingTrendAnalytics — finding trend analysis."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FindingCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    COMPLIANCE = "compliance"
    IDENTITY = "identity"
    DATA_EXPOSURE = "data_exposure"


class TrendPeriod(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


class VolumeChange(StrEnum):
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"
    SPIKE = "spike"


# --- Models ---


class FindingTrendRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    finding_category: FindingCategory = FindingCategory.VULNERABILITY
    trend_period: TrendPeriod = TrendPeriod.WEEKLY
    volume_change: VolumeChange = VolumeChange.STABLE
    score: float = 0.0
    finding_count: int = 0
    previous_count: int = 0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class FindingTrendAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    finding_category: FindingCategory = FindingCategory.VULNERABILITY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FindingTrendReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_finding_category: dict[str, int] = Field(default_factory=dict)
    by_trend_period: dict[str, int] = Field(default_factory=dict)
    by_volume_change: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class FindingTrendAnalytics:
    """Analyze security finding trends."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[FindingTrendRecord] = []
        self._analyses: list[FindingTrendAnalysis] = []
        logger.info(
            "finding_trend_analytics.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        finding_category: FindingCategory = (FindingCategory.VULNERABILITY),
        trend_period: TrendPeriod = (TrendPeriod.WEEKLY),
        volume_change: VolumeChange = (VolumeChange.STABLE),
        score: float = 0.0,
        finding_count: int = 0,
        previous_count: int = 0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> FindingTrendRecord:
        record = FindingTrendRecord(
            name=name,
            finding_category=finding_category,
            trend_period=trend_period,
            volume_change=volume_change,
            score=score,
            finding_count=finding_count,
            previous_count=previous_count,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "finding_trend.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> FindingTrendRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        finding_category: (FindingCategory | None) = None,
        volume_change: VolumeChange | None = None,
        limit: int = 50,
    ) -> list[FindingTrendRecord]:
        results = list(self._records)
        if finding_category is not None:
            results = [r for r in results if r.finding_category == finding_category]
        if volume_change is not None:
            results = [r for r in results if r.volume_change == volume_change]
        return results[-limit:]

    # -- domain methods ---

    def analyze_finding_trends(
        self,
    ) -> list[dict[str, Any]]:
        """Analyze trends by category."""
        cat_data: dict[str, list[FindingTrendRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.finding_category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, recs in cat_data.items():
            counts = [r.finding_count for r in recs]
            results.append(
                {
                    "category": cat,
                    "periods": len(recs),
                    "latest_count": counts[-1],
                    "avg_count": round(
                        sum(counts) / len(counts),
                        1,
                    ),
                    "trend": recs[-1].volume_change.value,
                }
            )
        return sorted(
            results,
            key=lambda x: x["latest_count"],
            reverse=True,
        )

    def predict_future_volume(
        self,
    ) -> list[dict[str, Any]]:
        """Predict future finding volumes."""
        results: list[dict[str, Any]] = []
        cat_data: dict[str, list[FindingTrendRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.finding_category.value, []).append(r)
        for cat, recs in cat_data.items():
            if len(recs) < 2:
                continue
            recent = recs[-1].finding_count
            prev = recs[-2].finding_count
            delta = recent - prev
            predicted = max(recent + delta, 0)
            results.append(
                {
                    "category": cat,
                    "current": recent,
                    "predicted_next": predicted,
                    "delta": delta,
                    "direction": ("up" if delta > 0 else ("down" if delta < 0 else "flat")),
                }
            )
        return results

    def identify_recurring_patterns(
        self,
    ) -> list[dict[str, Any]]:
        """Identify recurring finding patterns."""
        name_counts: dict[str, int] = {}
        for r in self._records:
            name_counts[r.name] = name_counts.get(r.name, 0) + 1
        recurring: list[dict[str, Any]] = []
        for name, count in name_counts.items():
            if count > 1:
                recurring.append(
                    {
                        "name": name,
                        "occurrences": count,
                        "recurring": count >= 3,
                    }
                )
        return sorted(
            recurring,
            key=lambda x: x["occurrences"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> FindingTrendReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.finding_category.value] = by_e1.get(r.finding_category.value, 0) + 1
            by_e2[r.trend_period.value] = by_e2.get(r.trend_period.value, 0) + 1
            by_e3[r.volume_change.value] = by_e3.get(r.volume_change.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Finding trends are healthy")
        return FindingTrendReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_finding_category=by_e1,
            by_trend_period=by_e2,
            by_volume_change=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.finding_category.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "category_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("finding_trend_analytics.cleared")
        return {"status": "cleared"}
