"""PipelinePerformanceAnalytics — pipeline perf."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PipelineMetric(StrEnum):
    CYCLE_TIME = "cycle_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    FINDING_VELOCITY = "finding_velocity"


class CycleTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"


class EfficiencyScore(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


# --- Models ---


class PipelinePerformanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pipeline_metric: PipelineMetric = PipelineMetric.CYCLE_TIME
    cycle_trend: CycleTrend = CycleTrend.STABLE
    efficiency_score: EfficiencyScore = EfficiencyScore.GOOD
    score: float = 0.0
    cycle_time_ms: float = 0.0
    findings_per_cycle: int = 0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelinePerformanceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pipeline_metric: PipelineMetric = PipelineMetric.CYCLE_TIME
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelinePerformanceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_pipeline_metric: dict[str, int] = Field(default_factory=dict)
    by_cycle_trend: dict[str, int] = Field(default_factory=dict)
    by_efficiency_score: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PipelinePerformanceAnalytics:
    """Analyze pipeline performance."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PipelinePerformanceRecord] = []
        self._analyses: list[PipelinePerformanceAnalysis] = []
        logger.info(
            "pipeline_performance_analytics.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        pipeline_metric: PipelineMetric = (PipelineMetric.CYCLE_TIME),
        cycle_trend: CycleTrend = (CycleTrend.STABLE),
        efficiency_score: EfficiencyScore = (EfficiencyScore.GOOD),
        score: float = 0.0,
        cycle_time_ms: float = 0.0,
        findings_per_cycle: int = 0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> PipelinePerformanceRecord:
        record = PipelinePerformanceRecord(
            name=name,
            pipeline_metric=pipeline_metric,
            cycle_trend=cycle_trend,
            efficiency_score=efficiency_score,
            score=score,
            cycle_time_ms=cycle_time_ms,
            findings_per_cycle=findings_per_cycle,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "pipeline_perf.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> PipelinePerformanceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pipeline_metric: (PipelineMetric | None) = None,
        cycle_trend: CycleTrend | None = None,
        limit: int = 50,
    ) -> list[PipelinePerformanceRecord]:
        results = list(self._records)
        if pipeline_metric is not None:
            results = [r for r in results if r.pipeline_metric == pipeline_metric]
        if cycle_trend is not None:
            results = [r for r in results if r.cycle_trend == cycle_trend]
        return results[-limit:]

    # -- domain methods ---

    def measure_cycle_time(
        self,
    ) -> list[dict[str, Any]]:
        """Measure cycle time per service."""
        svc_data: dict[str, list[float]] = {}
        for r in self._records:
            svc_data.setdefault(r.service or r.name, []).append(r.cycle_time_ms)
        results: list[dict[str, Any]] = []
        for svc, times in svc_data.items():
            avg = sum(times) / len(times)
            results.append(
                {
                    "service": svc,
                    "avg_cycle_ms": round(avg, 2),
                    "min_cycle_ms": min(times),
                    "max_cycle_ms": max(times),
                    "samples": len(times),
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_cycle_ms"],
            reverse=True,
        )

    def track_finding_velocity(
        self,
    ) -> dict[str, Any]:
        """Track finding processing velocity."""
        if not self._records:
            return {
                "total": 0,
                "velocity": 0.0,
            }
        total_findings = sum(r.findings_per_cycle for r in self._records)
        total_time = sum(r.cycle_time_ms for r in self._records)
        velocity = (
            round(
                total_findings / max(total_time / 1000, 1),
                2,
            )
            if total_time
            else 0.0
        )
        return {
            "total_findings": total_findings,
            "total_cycles": len(self._records),
            "velocity_per_sec": velocity,
            "avg_per_cycle": round(
                total_findings / len(self._records),
                2,
            ),
        }

    def calculate_roi(
        self,
    ) -> dict[str, Any]:
        """Calculate pipeline ROI metrics."""
        if not self._records:
            return {"roi_score": 0.0}
        scores = [r.score for r in self._records]
        avg_score = sum(scores) / len(scores)
        efficient = sum(
            1
            for r in self._records
            if r.efficiency_score
            in (
                EfficiencyScore.EXCELLENT,
                EfficiencyScore.GOOD,
            )
        )
        return {
            "roi_score": round(avg_score, 2),
            "efficiency_pct": round(
                efficient / len(self._records) * 100,
                1,
            ),
            "total_cycles": len(self._records),
        }

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
    ) -> PipelinePerformanceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.pipeline_metric.value] = by_e1.get(r.pipeline_metric.value, 0) + 1
            by_e2[r.cycle_trend.value] = by_e2.get(r.cycle_trend.value, 0) + 1
            by_e3[r.efficiency_score.value] = by_e3.get(r.efficiency_score.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Pipeline performance is healthy")
        return PipelinePerformanceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_pipeline_metric=by_e1,
            by_cycle_trend=by_e2,
            by_efficiency_score=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.pipeline_metric.value
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
        logger.info("pipeline_performance.cleared")
        return {"status": "cleared"}
