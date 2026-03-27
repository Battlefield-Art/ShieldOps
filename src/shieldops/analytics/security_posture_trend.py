"""SecurityPostureTrend -- track posture trends."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TrendPeriod(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


class PostureChange(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"


class DriverCategory(StrEnum):
    PATCH_MANAGEMENT = "patch_management"
    CONFIG_DRIFT = "config_drift"
    NEW_THREATS = "new_threats"
    STAFF_CHANGE = "staff_change"
    TOOL_DEPLOYMENT = "tool_deployment"


# --- Models ---


class SecurityPostureTrendRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    period: TrendPeriod = TrendPeriod.DAILY
    change: PostureChange = PostureChange.STABLE
    driver: DriverCategory = DriverCategory.PATCH_MANAGEMENT
    score: float = 0.0
    domain: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SecurityPostureTrendAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    period: TrendPeriod = TrendPeriod.DAILY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SecurityPostureTrendReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_period: dict[str, int] = Field(default_factory=dict)
    by_change: dict[str, int] = Field(default_factory=dict)
    by_driver: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SecurityPostureTrendEngine:
    """Track security posture trends over time."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SecurityPostureTrendRecord] = []
        self._analyses: list[SecurityPostureTrendAnalysis] = []
        logger.info(
            "security_posture_trend.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        period: TrendPeriod = TrendPeriod.DAILY,
        change: PostureChange = PostureChange.STABLE,
        driver: DriverCategory = DriverCategory.PATCH_MANAGEMENT,
        score: float = 0.0,
        domain: str = "",
        service: str = "",
        team: str = "",
    ) -> SecurityPostureTrendRecord:
        record = SecurityPostureTrendRecord(
            name=name,
            period=period,
            change=change,
            driver=driver,
            score=score,
            domain=domain,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "security_posture_trend.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> SecurityPostureTrendRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        period: TrendPeriod | None = None,
        change: PostureChange | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SecurityPostureTrendRecord]:
        results = list(self._records)
        if period is not None:
            results = [r for r in results if r.period == period]
        if change is not None:
            results = [r for r in results if r.change == change]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        period: TrendPeriod = TrendPeriod.DAILY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SecurityPostureTrendAnalysis:
        analysis = SecurityPostureTrendAnalysis(
            name=name,
            period=period,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def calculate_trend(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate trend per domain."""
        domain_data: dict[
            str,
            list[SecurityPostureTrendRecord],
        ] = {}
        for r in self._records:
            domain_data.setdefault(r.domain, []).append(r)
        results: list[dict[str, Any]] = []
        for domain, records in domain_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            latest = records[-1].change.value
            results.append(
                {
                    "domain": domain,
                    "avg_score": avg,
                    "latest_change": latest,
                    "count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def identify_drivers(
        self,
    ) -> dict[str, Any]:
        """Identify posture change drivers."""
        driver_scores: dict[str, list[float]] = {}
        for r in self._records:
            driver_scores.setdefault(r.driver.value, []).append(r.score)
        result: dict[str, Any] = {}
        for driver, scores in driver_scores.items():
            avg = sum(scores) / len(scores)
            result[driver] = {
                "avg_score": round(avg, 2),
                "count": len(scores),
            }
        return result

    def forecast_posture(
        self,
    ) -> dict[str, Any]:
        """Forecast posture direction."""
        if len(self._records) < 2:
            return {
                "direction": "insufficient_data",
                "samples": len(self._records),
            }
        half = len(self._records) // 2
        first = self._records[:half]
        second = self._records[half:]
        avg_first = sum(r.score for r in first) / len(first)
        avg_second = sum(r.score for r in second) / len(second)
        delta = avg_second - avg_first
        direction = "improving" if delta > 1.0 else "degrading" if delta < -1.0 else "stable"
        return {
            "direction": direction,
            "early_avg": round(avg_first, 2),
            "recent_avg": round(avg_second, 2),
            "delta": round(delta, 2),
            "samples": len(self._records),
        }

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "period": r.period.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.domain == key]
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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> SecurityPostureTrendReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.period.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.change.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.driver.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Security Posture Trend healthy")
        return SecurityPostureTrendReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_period=by_e1,
            by_change=by_e2,
            by_driver=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("security_posture_trend.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.period.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "period_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
