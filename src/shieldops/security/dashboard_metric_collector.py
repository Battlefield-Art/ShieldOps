"""DashboardMetricCollector — collect dashboard metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MetricSource(StrEnum):
    AGENT = "agent"
    ENGINE = "engine"
    CONNECTOR = "connector"
    EXTERNAL = "external"


class FreshnessGrade(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"


class AggregationMethod(StrEnum):
    SUM = "sum"
    AVERAGE = "average"
    MAX = "max"
    COUNT = "count"
    PERCENTILE = "percentile"


# --- Models ---


class DashboardMetricRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    metric_source: MetricSource = MetricSource.AGENT
    freshness_grade: FreshnessGrade = FreshnessGrade.FRESH
    aggregation_method: AggregationMethod = AggregationMethod.AVERAGE
    score: float = 0.0
    metric_value: float = 0.0
    last_updated: float = Field(default_factory=time.time)
    domain: str = ""
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DashboardMetricAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    metric_source: MetricSource = MetricSource.AGENT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DashboardMetricReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_metric_source: dict[str, int] = Field(default_factory=dict)
    by_freshness_grade: dict[str, int] = Field(default_factory=dict)
    by_aggregation_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DashboardMetricCollector:
    """Collect and assess dashboard metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DashboardMetricRecord] = []
        self._analyses: list[DashboardMetricAnalysis] = []
        logger.info(
            "dashboard_metric_collector.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        metric_source: MetricSource = (MetricSource.AGENT),
        freshness_grade: FreshnessGrade = (FreshnessGrade.FRESH),
        aggregation_method: AggregationMethod = (AggregationMethod.AVERAGE),
        score: float = 0.0,
        metric_value: float = 0.0,
        domain: str = "",
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> DashboardMetricRecord:
        record = DashboardMetricRecord(
            name=name,
            metric_source=metric_source,
            freshness_grade=freshness_grade,
            aggregation_method=aggregation_method,
            score=score,
            metric_value=metric_value,
            domain=domain,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "dashboard_metric.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> DashboardMetricRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        metric_source: MetricSource | None = None,
        freshness_grade: (FreshnessGrade | None) = None,
        limit: int = 50,
    ) -> list[DashboardMetricRecord]:
        results = list(self._records)
        if metric_source is not None:
            results = [r for r in results if r.metric_source == metric_source]
        if freshness_grade is not None:
            results = [r for r in results if r.freshness_grade == freshness_grade]
        return results[-limit:]

    # -- domain methods ---

    def collect_from_agent(
        self,
    ) -> list[dict[str, Any]]:
        """Collect metrics from agent sources."""
        agent_recs = [r for r in self._records if r.metric_source == MetricSource.AGENT]
        domain_data: dict[str, list[DashboardMetricRecord]] = {}
        for r in agent_recs:
            domain_data.setdefault(r.domain or "unknown", []).append(r)
        results: list[dict[str, Any]] = []
        for domain, recs in domain_data.items():
            vals = [r.metric_value for r in recs]
            results.append(
                {
                    "domain": domain,
                    "metric_count": len(recs),
                    "avg_value": round(sum(vals) / len(vals), 2),
                    "latest": recs[-1].name,
                }
            )
        return sorted(
            results,
            key=lambda x: x["metric_count"],
            reverse=True,
        )

    def assess_freshness(
        self,
    ) -> dict[str, Any]:
        """Assess freshness of all metrics."""
        grade_counts: dict[str, int] = {}
        for r in self._records:
            k = r.freshness_grade.value
            grade_counts[k] = grade_counts.get(k, 0) + 1
        total = len(self._records) or 1
        fresh = grade_counts.get("fresh", 0)
        return {
            "total_metrics": len(self._records),
            "freshness_distribution": grade_counts,
            "freshness_pct": round(fresh / total * 100, 1),
            "stale_count": grade_counts.get("stale", 0),
            "expired_count": grade_counts.get("expired", 0),
        }

    def aggregate_by_domain(
        self,
    ) -> list[dict[str, Any]]:
        """Aggregate metrics by domain."""
        domain_data: dict[str, list[float]] = {}
        for r in self._records:
            domain_data.setdefault(r.domain or "unknown", []).append(r.metric_value)
        results: list[dict[str, Any]] = []
        for domain, vals in domain_data.items():
            results.append(
                {
                    "domain": domain,
                    "count": len(vals),
                    "sum": round(sum(vals), 2),
                    "avg": round(sum(vals) / len(vals), 2),
                    "max": max(vals),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
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
    ) -> DashboardMetricReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.metric_source.value] = by_e1.get(r.metric_source.value, 0) + 1
            by_e2[r.freshness_grade.value] = by_e2.get(r.freshness_grade.value, 0) + 1
            by_e3[r.aggregation_method.value] = by_e3.get(r.aggregation_method.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Dashboard metrics are healthy")
        return DashboardMetricReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_metric_source=by_e1,
            by_freshness_grade=by_e2,
            by_aggregation_method=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.metric_source.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "source_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("dashboard_metric_collector.cleared")
        return {"status": "cleared"}
