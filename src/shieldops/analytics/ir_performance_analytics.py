"""IR Performance Analytics — measure IR response metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IRMetric(StrEnum):
    MTTR = "mttr"
    MTTD = "mttd"
    MTTC = "mttc"
    MTTE = "mtte"
    MTTR_FULL = "mttr_full"


class ResponseSpeed(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    SLOW = "slow"
    CRITICAL = "critical"


class OutcomeTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


# --- Models ---


class IRPerformanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    metric: IRMetric = IRMetric.MTTR
    speed: ResponseSpeed = ResponseSpeed.GOOD
    trend: OutcomeTrend = OutcomeTrend.STABLE
    value_minutes: float = 0.0
    target_minutes: float = 0.0
    incident_type: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class IRPerformanceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    metric: IRMetric = IRMetric.MTTR
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IRPerformanceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_mttr_min: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_speed: dict[str, int] = Field(default_factory=dict)
    by_trend: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class IRPerformanceAnalyticsEngine:
    """Measure and analyze IR response metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        mttr_threshold_min: float = 60.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = mttr_threshold_min
        self._records: list[IRPerformanceRecord] = []
        self._analyses: list[IRPerformanceAnalysis] = []
        logger.info(
            "ir_performance_analytics.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        incident_id: str,
        metric: IRMetric = IRMetric.MTTR,
        speed: ResponseSpeed = ResponseSpeed.GOOD,
        trend: OutcomeTrend = OutcomeTrend.STABLE,
        value_minutes: float = 0.0,
        target_minutes: float = 0.0,
        incident_type: str = "",
        service: str = "",
        team: str = "",
    ) -> IRPerformanceRecord:
        record = IRPerformanceRecord(
            incident_id=incident_id,
            metric=metric,
            speed=speed,
            trend=trend,
            value_minutes=value_minutes,
            target_minutes=target_minutes,
            incident_type=incident_type,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ir_performance_analytics.record_added",
            record_id=record.id,
            metric=metric.value,
        )
        return record

    def get_record(self, record_id: str) -> IRPerformanceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        metric: IRMetric | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[IRPerformanceRecord]:
        results = list(self._records)
        if metric is not None:
            results = [r for r in results if r.metric == metric]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations ---

    def measure_mttr(
        self,
    ) -> list[dict[str, Any]]:
        """Measure MTTR by team."""
        team_data: dict[str, list[IRPerformanceRecord]] = {}
        for r in self._records:
            if r.metric == IRMetric.MTTR:
                team_data.setdefault(r.team or "unknown", []).append(r)
        results: list[dict[str, Any]] = []
        for t, records in team_data.items():
            vals = [r.value_minutes for r in records]
            avg = round(sum(vals) / len(vals), 2) if vals else 0.0
            results.append(
                {
                    "team": t,
                    "count": len(records),
                    "avg_mttr_min": avg,
                    "meets_target": avg <= self._threshold,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_mttr_min"],
        )

    def track_containment_speed(
        self,
    ) -> list[dict[str, Any]]:
        """Track containment speed by type."""
        type_data: dict[str, list[IRPerformanceRecord]] = {}
        for r in self._records:
            if r.metric == IRMetric.MTTC:
                type_data.setdefault(r.incident_type or "unknown", []).append(r)
        results: list[dict[str, Any]] = []
        for itype, records in type_data.items():
            vals = [r.value_minutes for r in records]
            avg = round(sum(vals) / len(vals), 2) if vals else 0.0
            results.append(
                {
                    "incident_type": itype,
                    "count": len(records),
                    "avg_contain_min": avg,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_contain_min"],
        )

    def benchmark_response(
        self,
    ) -> list[dict[str, Any]]:
        """Benchmark response vs targets."""
        metric_data: dict[str, list[IRPerformanceRecord]] = {}
        for r in self._records:
            metric_data.setdefault(r.metric.value, []).append(r)
        results: list[dict[str, Any]] = []
        for m, records in metric_data.items():
            vals = [r.value_minutes for r in records]
            targets = [r.target_minutes for r in records if r.target_minutes > 0]
            avg_val = round(sum(vals) / len(vals), 2) if vals else 0.0
            avg_tgt = round(sum(targets) / len(targets), 2) if targets else 0.0
            met = sum(
                1 for r in records if r.target_minutes > 0 and r.value_minutes <= r.target_minutes
            )
            results.append(
                {
                    "metric": m,
                    "count": len(records),
                    "avg_value_min": avg_val,
                    "avg_target_min": avg_tgt,
                    "targets_met": met,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_value_min"],
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.incident_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        vals = [r.value_minutes for r in matched]
        avg = round(sum(vals) / len(vals), 2) if vals else 0.0
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_value_min": avg,
        }

    def generate_report(
        self,
    ) -> IRPerformanceReport:
        by_m: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_t: dict[str, int] = {}
        for r in self._records:
            by_m[r.metric.value] = by_m.get(r.metric.value, 0) + 1
            by_s[r.speed.value] = by_s.get(r.speed.value, 0) + 1
            by_t[r.trend.value] = by_t.get(r.trend.value, 0) + 1
        mttr_recs = [r for r in self._records if r.metric == IRMetric.MTTR]
        vals = [r.value_minutes for r in mttr_recs]
        avg_mttr = round(sum(vals) / len(vals), 2) if vals else 0.0
        recs: list[str] = []
        if avg_mttr > self._threshold:
            recs.append(f"MTTR {avg_mttr}m exceeds {self._threshold}m")
        if not recs:
            recs.append("IR Performance Analytics healthy")
        return IRPerformanceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_mttr_min=avg_mttr,
            by_metric=by_m,
            by_speed=by_s,
            by_trend=by_t,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ir_performance_analytics.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        m_dist: dict[str, int] = {}
        for r in self._records:
            k = r.metric.value
            m_dist[k] = m_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "mttr_threshold_min": self._threshold,
            "metric_distribution": m_dist,
            "unique_incidents": len({r.incident_id for r in self._records}),
        }
