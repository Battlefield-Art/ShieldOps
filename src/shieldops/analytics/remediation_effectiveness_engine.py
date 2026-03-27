"""Remediation Effectiveness Engine — measure ROI."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EffectivenessMetric(StrEnum):
    MTTR = "mttr"
    RECURRENCE_RATE = "recurrence_rate"
    FIRST_FIX_RATE = "first_fix_rate"
    AUTOMATION_RATE = "automation_rate"
    COVERAGE = "coverage"


class TrendDirection(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    VOLATILE = "volatile"
    INSUFFICIENT_DATA = "insufficient_data"


class ROICategory(StrEnum):
    HIGH_ROI = "high_roi"
    MODERATE_ROI = "moderate_roi"
    LOW_ROI = "low_roi"
    NEGATIVE_ROI = "negative_roi"
    UNKNOWN = "unknown"


# --- Models ---


class EffectivenessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    remediation_id: str = ""
    metric: EffectivenessMetric = EffectivenessMetric.MTTR
    trend: TrendDirection = TrendDirection.INSUFFICIENT_DATA
    roi: ROICategory = ROICategory.UNKNOWN
    value: float = 0.0
    cost_dollars: float = 0.0
    time_saved_hours: float = 0.0
    created_at: float = Field(default_factory=time.time)


class EffectivenessAnalysis(BaseModel):
    remediation_id: str = ""
    metrics_count: int = 0
    avg_value: float = 0.0
    overall_trend: str = ""
    total_roi_dollars: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class EffectivenessReport(BaseModel):
    total_records: int = 0
    avg_effectiveness: float = 0.0
    total_cost_dollars: float = 0.0
    total_time_saved_hours: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_roi: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RemediationEffectivenessEngine:
    """Measure remediation effectiveness and ROI."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[EffectivenessRecord] = []
        logger.info(
            "remediation_effectiveness.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> EffectivenessRecord:
        rec = EffectivenessRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "remediation_effectiveness.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, remediation_id: str) -> EffectivenessAnalysis:
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return EffectivenessAnalysis(remediation_id=remediation_id)
        vals = [r.value for r in recs]
        avg_v = round(sum(vals) / len(vals), 2)
        improving = sum(1 for r in recs if r.trend == TrendDirection.IMPROVING)
        declining = sum(1 for r in recs if r.trend == TrendDirection.DECLINING)
        if improving > declining:
            trend = "improving"
        elif declining > improving:
            trend = "declining"
        else:
            trend = "stable"
        saved = sum(r.time_saved_hours for r in recs)
        cost = sum(r.cost_dollars for r in recs)
        roi = round(saved * 50 - cost, 2)
        return EffectivenessAnalysis(
            remediation_id=remediation_id,
            metrics_count=len(recs),
            avg_value=avg_v,
            overall_trend=trend,
            total_roi_dollars=roi,
        )

    def generate_report(
        self,
    ) -> EffectivenessReport:
        by_metric: dict[str, int] = {}
        by_roi: dict[str, int] = {}
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            c = r.roi.value
            by_roi[c] = by_roi.get(c, 0) + 1
        total = len(self._records)
        vals = [r.value for r in self._records]
        avg = round(sum(vals) / len(vals), 2) if vals else 0.0
        cost = sum(r.cost_dollars for r in self._records)
        saved = sum(r.time_saved_hours for r in self._records)
        recs: list[str] = []
        neg = by_roi.get("negative_roi", 0)
        if neg > 0:
            recs.append(f"{neg} negative-ROI remediation(s)")
        if avg < 0.5:
            recs.append("Avg effectiveness below 50%")
        if not recs:
            recs.append("Remediation effectiveness healthy")
        return EffectivenessReport(
            total_records=total,
            avg_effectiveness=avg,
            total_cost_dollars=round(cost, 2),
            total_time_saved_hours=round(saved, 2),
            by_metric=by_metric,
            by_roi=by_roi,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_remediations": len({r.remediation_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("remediation_effectiveness.cleared")

    # -- domain methods --

    def measure_effectiveness(
        self,
        metric: EffectivenessMetric,
        remediation_id: str = "",
    ) -> dict[str, Any]:
        """Measure a specific effectiveness metric."""
        recs = [r for r in self._records if r.metric == metric]
        if remediation_id:
            recs = [r for r in recs if r.remediation_id == remediation_id]
        vals = [r.value for r in recs]
        avg = round(sum(vals) / len(vals), 2) if vals else 0.0
        return {
            "metric": metric.value,
            "count": len(recs),
            "avg_value": avg,
            "min_value": (round(min(vals), 2) if vals else 0.0),
            "max_value": (round(max(vals), 2) if vals else 0.0),
        }

    def calculate_roi(
        self,
        remediation_id: str | None = None,
    ) -> dict[str, Any]:
        """Calculate ROI for remediations."""
        recs = self._records
        if remediation_id:
            recs = [r for r in recs if r.remediation_id == remediation_id]
        cost = sum(r.cost_dollars for r in recs)
        saved = sum(r.time_saved_hours for r in recs)
        value = round(saved * 50, 2)
        roi = round((value - cost) / cost * 100, 2) if cost > 0 else 0.0
        return {
            "total_cost": round(cost, 2),
            "time_saved_hours": round(saved, 2),
            "value_dollars": value,
            "roi_pct": roi,
        }

    def track_trend(
        self,
        metric: EffectivenessMetric,
        window: int = 10,
    ) -> dict[str, Any]:
        """Track trend for a metric."""
        recs = [r for r in self._records if r.metric == metric][-window:]
        if len(recs) < 3:
            return {
                "metric": metric.value,
                "trend": "insufficient_data",
                "data_points": len(recs),
            }
        vals = [r.value for r in recs]
        half = len(vals) // 2
        first_avg = sum(vals[:half]) / half
        second_avg = sum(vals[half:]) / (len(vals) - half)
        if second_avg > first_avg * 1.05:
            trend = "improving"
        elif second_avg < first_avg * 0.95:
            trend = "declining"
        else:
            trend = "stable"
        return {
            "metric": metric.value,
            "trend": trend,
            "data_points": len(recs),
            "first_half_avg": round(first_avg, 2),
            "second_half_avg": round(second_avg, 2),
        }
