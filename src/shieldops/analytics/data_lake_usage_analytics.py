"""Data Lake Usage Analytics — query patterns and data growth."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class QueryPattern(StrEnum):
    AD_HOC = "ad_hoc"
    SCHEDULED = "scheduled"
    STREAMING = "streaming"
    BATCH = "batch"
    INTERACTIVE = "interactive"


class DataVolume(StrEnum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    VERY_LARGE = "very_large"


class AccessFrequency(StrEnum):
    RARE = "rare"
    OCCASIONAL = "occasional"
    FREQUENT = "frequent"
    CONTINUOUS = "continuous"


# --- Models ---


class UsageRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dataset_name: str = ""
    pattern: QueryPattern = QueryPattern.AD_HOC
    volume: DataVolume = DataVolume.MEDIUM
    frequency: AccessFrequency = AccessFrequency.OCCASIONAL
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class UsageAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dataset_name: str = ""
    pattern: QueryPattern = QueryPattern.AD_HOC
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class UsageReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_pattern: dict[str, int] = Field(default_factory=dict)
    by_volume: dict[str, int] = Field(default_factory=dict)
    by_frequency: dict[str, int] = Field(default_factory=dict)
    hot_datasets: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataLakeUsageAnalytics:
    """Analyze data lake query patterns and growth."""

    def __init__(
        self,
        max_records: int = 200000,
        growth_threshold: float = 80.0,
    ) -> None:
        self._max = max_records
        self._threshold = growth_threshold
        self._records: list[UsageRecord] = []
        self._analyses: list[UsageAnalysis] = []
        logger.info(
            "data_lake_usage_analytics.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        dataset_name: str = "",
        pattern: QueryPattern = QueryPattern.AD_HOC,
        volume: DataVolume = DataVolume.MEDIUM,
        frequency: AccessFrequency = (AccessFrequency.OCCASIONAL),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> UsageRecord:
        rec = UsageRecord(
            dataset_name=dataset_name,
            pattern=pattern,
            volume=volume,
            frequency=frequency,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "data_lake_usage.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> UsageAnalysis:
        matches = [r for r in self._records if r.dataset_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = UsageAnalysis(
            dataset_name=key,
            analysis_score=round(avg, 2),
            threshold=self._threshold,
            breached=avg > self._threshold,
            description=(f"Analyzed {len(matches)} datasets"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def analyze_query_patterns(
        self,
    ) -> dict[str, Any]:
        """Aggregate query pattern distribution."""
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.pattern.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "distribution": dist,
            "total": len(self._records),
        }

    def track_data_growth(
        self,
    ) -> dict[str, Any]:
        """Split-half trend on data volume scores."""
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
            trend = "growing"
        else:
            trend = "shrinking"
        return {
            "trend": trend,
            "delta": delta,
            "first_avg": round(first, 2),
            "second_avg": round(second, 2),
        }

    def optimize_retention(
        self,
    ) -> list[dict[str, Any]]:
        """Find rarely accessed large datasets."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.frequency == AccessFrequency.RARE and r.volume in (
                DataVolume.LARGE,
                DataVolume.VERY_LARGE,
            ):
                results.append(
                    {
                        "id": r.id,
                        "dataset": r.dataset_name,
                        "volume": r.volume.value,
                        "frequency": r.frequency.value,
                    }
                )
        return results

    # -- report / stats ---

    def generate_report(self) -> UsageReport:
        by_pattern: dict[str, int] = {}
        by_volume: dict[str, int] = {}
        by_freq: dict[str, int] = {}
        for r in self._records:
            p = r.pattern.value
            by_pattern[p] = by_pattern.get(p, 0) + 1
            v = r.volume.value
            by_volume[v] = by_volume.get(v, 0) + 1
            f = r.frequency.value
            by_freq[f] = by_freq.get(f, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        hot = [r.dataset_name for r in self._records if r.frequency == AccessFrequency.CONTINUOUS][
            :5
        ]
        recs: list[str] = []
        if hot:
            recs.append(f"{len(hot)} dataset(s) accessed continuously")
        if not recs:
            recs.append("Data lake usage is normal")
        return UsageReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_pattern=by_pattern,
            by_volume=by_volume,
            by_frequency=by_freq,
            hot_datasets=hot,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.pattern.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "pattern_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("data_lake_usage_analytics.cleared")
        return {"status": "cleared"}
