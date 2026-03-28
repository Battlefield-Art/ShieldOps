"""KPIDashboardAnalytics — KPI tracking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class KPICategory(StrEnum):
    SECURITY = "security"
    OPERATIONAL = "operational"
    COMPLIANCE = "compliance"
    FINANCIAL = "financial"


class TargetStatus(StrEnum):
    ON_TARGET = "on_target"
    AT_RISK = "at_risk"
    MISSED = "missed"
    EXCEEDED = "exceeded"


class BoardMetric(StrEnum):
    MTTR = "mttr"
    MTTD = "mttd"
    INCIDENT_RATE = "incident_rate"
    COMPLIANCE_SCORE = "compliance_score"
    COST_PER_FINDING = "cost_per_finding"


# --- Models ---


class KPIDashboardRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    kpi_category: KPICategory = KPICategory.SECURITY
    target_status: TargetStatus = TargetStatus.ON_TARGET
    board_metric: BoardMetric = BoardMetric.MTTR
    score: float = 0.0
    target_value: float = 0.0
    actual_value: float = 0.0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class KPIDashboardAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    kpi_category: KPICategory = KPICategory.SECURITY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KPIDashboardReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_kpi_category: dict[str, int] = Field(default_factory=dict)
    by_target_status: dict[str, int] = Field(default_factory=dict)
    by_board_metric: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class KPIDashboardAnalytics:
    """Track and analyze KPIs."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[KPIDashboardRecord] = []
        self._analyses: list[KPIDashboardAnalysis] = []
        logger.info(
            "kpi_dashboard_analytics.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        kpi_category: KPICategory = (KPICategory.SECURITY),
        target_status: TargetStatus = (TargetStatus.ON_TARGET),
        board_metric: BoardMetric = (BoardMetric.MTTR),
        score: float = 0.0,
        target_value: float = 0.0,
        actual_value: float = 0.0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> KPIDashboardRecord:
        record = KPIDashboardRecord(
            name=name,
            kpi_category=kpi_category,
            target_status=target_status,
            board_metric=board_metric,
            score=score,
            target_value=target_value,
            actual_value=actual_value,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "kpi_dashboard.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> KPIDashboardRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        kpi_category: KPICategory | None = None,
        target_status: TargetStatus | None = None,
        limit: int = 50,
    ) -> list[KPIDashboardRecord]:
        results = list(self._records)
        if kpi_category is not None:
            results = [r for r in results if r.kpi_category == kpi_category]
        if target_status is not None:
            results = [r for r in results if r.target_status == target_status]
        return results[-limit:]

    # -- domain methods ---

    def calculate_kpi(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate KPI achievement per metric."""
        metric_data: dict[str, list[KPIDashboardRecord]] = {}
        for r in self._records:
            metric_data.setdefault(r.board_metric.value, []).append(r)
        results: list[dict[str, Any]] = []
        for metric, recs in metric_data.items():
            targets = [r.target_value for r in recs]
            actuals = [r.actual_value for r in recs]
            avg_target = sum(targets) / len(targets)
            avg_actual = sum(actuals) / len(actuals)
            results.append(
                {
                    "metric": metric,
                    "avg_target": round(avg_target, 2),
                    "avg_actual": round(avg_actual, 2),
                    "achievement_pct": round(
                        avg_actual / max(avg_target, 1) * 100,
                        1,
                    ),
                    "samples": len(recs),
                }
            )
        return sorted(
            results,
            key=lambda x: x["achievement_pct"],
        )

    def compare_to_target(
        self,
    ) -> list[dict[str, Any]]:
        """Compare actuals to targets."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            gap = round(
                r.actual_value - r.target_value,
                2,
            )
            results.append(
                {
                    "name": r.name,
                    "metric": (r.board_metric.value),
                    "target": r.target_value,
                    "actual": r.actual_value,
                    "gap": gap,
                    "status": (r.target_status.value),
                }
            )
        return sorted(results, key=lambda x: x["gap"])

    def generate_board_summary(
        self,
    ) -> dict[str, Any]:
        """Generate board-level summary."""
        if not self._records:
            return {"total_kpis": 0}
        on_target = sum(1 for r in self._records if r.target_status == TargetStatus.ON_TARGET)
        exceeded = sum(1 for r in self._records if r.target_status == TargetStatus.EXCEEDED)
        missed = sum(1 for r in self._records if r.target_status == TargetStatus.MISSED)
        cat_scores: dict[str, list[float]] = {}
        for r in self._records:
            cat_scores.setdefault(r.kpi_category.value, []).append(r.score)
        cat_avgs = {k: round(sum(v) / len(v), 2) for k, v in cat_scores.items()}
        return {
            "total_kpis": len(self._records),
            "on_target": on_target,
            "exceeded": exceeded,
            "missed": missed,
            "health_pct": round(
                (on_target + exceeded) / len(self._records) * 100,
                1,
            ),
            "category_scores": cat_avgs,
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
    ) -> KPIDashboardReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.kpi_category.value] = by_e1.get(r.kpi_category.value, 0) + 1
            by_e2[r.target_status.value] = by_e2.get(r.target_status.value, 0) + 1
            by_e3[r.board_metric.value] = by_e3.get(r.board_metric.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("KPI dashboard is healthy")
        return KPIDashboardReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_kpi_category=by_e1,
            by_target_status=by_e2,
            by_board_metric=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.kpi_category.value
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
        logger.info("kpi_dashboard_analytics.cleared")
        return {"status": "cleared"}
