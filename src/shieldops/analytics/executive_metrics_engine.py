"""ExecutiveMetricsEngine -- executive-level metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MetricCategory(StrEnum):
    RISK = "risk"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    COVERAGE = "coverage"


class AudienceLevel(StrEnum):
    CISO = "ciso"
    VP = "vp"
    DIRECTOR = "director"
    MANAGER = "manager"
    BOARD = "board"


class ReportFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


# --- Models ---


class ExecutiveMetricsRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: MetricCategory = MetricCategory.RISK
    audience: AudienceLevel = AudienceLevel.CISO
    frequency: ReportFrequency = ReportFrequency.WEEKLY
    score: float = 0.0
    metric_value: float = 0.0
    unit: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExecutiveMetricsAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: MetricCategory = MetricCategory.RISK
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExecutiveMetricsReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_audience: dict[str, int] = Field(default_factory=dict)
    by_frequency: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExecutiveMetricsEngine:
    """Collect and aggregate executive metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ExecutiveMetricsRecord] = []
        self._analyses: list[ExecutiveMetricsAnalysis] = []
        logger.info(
            "executive_metrics_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        category: MetricCategory = MetricCategory.RISK,
        audience: AudienceLevel = AudienceLevel.CISO,
        frequency: ReportFrequency = ReportFrequency.WEEKLY,
        score: float = 0.0,
        metric_value: float = 0.0,
        unit: str = "",
        service: str = "",
        team: str = "",
    ) -> ExecutiveMetricsRecord:
        record = ExecutiveMetricsRecord(
            name=name,
            category=category,
            audience=audience,
            frequency=frequency,
            score=score,
            metric_value=metric_value,
            unit=unit,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "executive_metrics_engine.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> ExecutiveMetricsRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: MetricCategory | None = None,
        audience: AudienceLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ExecutiveMetricsRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if audience is not None:
            results = [r for r in results if r.audience == audience]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        category: MetricCategory = MetricCategory.RISK,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ExecutiveMetricsAnalysis:
        analysis = ExecutiveMetricsAnalysis(
            name=name,
            category=category,
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

    def collect_metrics(
        self,
    ) -> list[dict[str, Any]]:
        """Collect metrics by category."""
        cat_data: dict[str, list[ExecutiveMetricsRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            results.append(
                {
                    "category": cat,
                    "avg_score": avg,
                    "count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def aggregate_for_audience(
        self,
    ) -> dict[str, Any]:
        """Aggregate metrics per audience level."""
        aud_data: dict[str, list[float]] = {}
        for r in self._records:
            aud_data.setdefault(r.audience.value, []).append(r.score)
        result: dict[str, Any] = {}
        for aud, scores in aud_data.items():
            avg = sum(scores) / len(scores)
            result[aud] = {
                "avg_score": round(avg, 2),
                "count": len(scores),
            }
        return result

    def generate_summary(
        self,
    ) -> dict[str, Any]:
        """Generate executive summary."""
        if not self._records:
            return {
                "status": "no_data",
                "total": 0,
            }
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2)
        above = sum(1 for s in scores if s >= self._threshold)
        return {
            "total_metrics": len(self._records),
            "avg_score": avg,
            "above_threshold": above,
            "below_threshold": len(scores) - above,
            "health": ("good" if avg >= self._threshold else "needs_attention"),
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
                        "category": r.category.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> ExecutiveMetricsReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.category.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.audience.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.frequency.value
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
            recs.append("Executive Metrics Engine healthy")
        return ExecutiveMetricsReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_category=by_e1,
            by_audience=by_e2,
            by_frequency=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("executive_metrics_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
