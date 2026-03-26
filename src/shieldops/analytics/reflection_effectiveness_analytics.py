"""Reflection Effectiveness Analytics — measure reflection ROI."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReflectionMetric(StrEnum):
    MISTAKE_REDUCTION = "mistake_reduction"
    THRESHOLD_ACCURACY = "threshold_accuracy"
    PLAYBOOK_EFFECTIVENESS = "playbook_effectiveness"


class ImprovementArea(StrEnum):
    DETECTION = "detection"
    RESPONSE = "response"
    TRIAGE = "triage"
    ESCALATION = "escalation"


class ROI(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGATIVE = "negative"


# --- Models ---


class ReflectionEffRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    metric: ReflectionMetric = ReflectionMetric.MISTAKE_REDUCTION
    area: ImprovementArea = ImprovementArea.DETECTION
    roi: ROI = ROI.MEDIUM
    before_value: float = 0.0
    after_value: float = 0.0
    improvement_pct: float = 0.0
    time_invested_seconds: float = 0.0
    created_at: float = Field(default_factory=time.time)


class ReflectionEffAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    total_records: int = 0
    avg_improvement: float = 0.0
    avg_roi: str = ""
    best_area: str = ""
    worst_area: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class ReflectionEffReport(BaseModel):
    total_records: int = 0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_area: dict[str, int] = Field(default_factory=dict)
    by_roi: dict[str, int] = Field(default_factory=dict)
    avg_improvement_pct: float = 0.0
    negative_roi_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ReflectionEffectivenessEngine:
    """Measure reflection effectiveness and ROI."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[ReflectionEffRecord] = []
        logger.info(
            "reflection_effectiveness.initialized",
            max_records=max_records,
        )

    def _compute_roi(
        self,
        improvement_pct: float,
        time_invested: float,
    ) -> ROI:
        if improvement_pct <= 0:
            return ROI.NEGATIVE
        efficiency = improvement_pct / max(time_invested, 1.0)
        if efficiency > 0.1:
            return ROI.HIGH
        if efficiency > 0.01:
            return ROI.MEDIUM
        return ROI.LOW

    # -- record / query --

    def add_record(
        self,
        agent_id: str,
        metric: ReflectionMetric = (ReflectionMetric.MISTAKE_REDUCTION),
        area: ImprovementArea = (ImprovementArea.DETECTION),
        before_value: float = 0.0,
        after_value: float = 0.0,
        time_invested_seconds: float = 0.0,
    ) -> ReflectionEffRecord:
        improvement = 0.0
        if before_value > 0:
            improvement = round(
                (after_value - before_value) / before_value * 100,
                2,
            )
        roi = self._compute_roi(improvement, time_invested_seconds)
        record = ReflectionEffRecord(
            agent_id=agent_id,
            metric=metric,
            area=area,
            roi=roi,
            before_value=before_value,
            after_value=after_value,
            improvement_pct=improvement,
            time_invested_seconds=(time_invested_seconds),
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "reflection_effectiveness.record_added",
            record_id=record.id,
            agent_id=agent_id,
            roi=roi.value,
        )
        return record

    def process(self, agent_id: str) -> ReflectionEffAnalysis:
        items = [r for r in self._records if r.agent_id == agent_id]
        if not items:
            return ReflectionEffAnalysis(agent_id=agent_id)
        avg_imp = round(
            sum(r.improvement_pct for r in items) / len(items),
            2,
        )
        roi_counts: dict[str, int] = {}
        for r in items:
            key = r.roi.value
            roi_counts[key] = roi_counts.get(key, 0) + 1
        avg_roi = (
            max(
                roi_counts,
                key=roi_counts.get,  # type: ignore[arg-type]
            )
            if roi_counts
            else ""
        )
        area_avgs: dict[str, float] = {}
        for r in items:
            area_avgs.setdefault(r.area.value, 0.0)
            area_avgs[r.area.value] += r.improvement_pct
        area_counts: dict[str, int] = {}
        for r in items:
            area_counts[r.area.value] = area_counts.get(r.area.value, 0) + 1
        for a in area_avgs:
            area_avgs[a] /= max(area_counts.get(a, 1), 1)
        best = (
            max(
                area_avgs,
                key=area_avgs.get,  # type: ignore[arg-type]
            )
            if area_avgs
            else ""
        )
        worst = (
            min(
                area_avgs,
                key=area_avgs.get,  # type: ignore[arg-type]
            )
            if area_avgs
            else ""
        )
        return ReflectionEffAnalysis(
            agent_id=agent_id,
            total_records=len(items),
            avg_improvement=avg_imp,
            avg_roi=avg_roi,
            best_area=best,
            worst_area=worst,
        )

    def generate_report(
        self,
    ) -> ReflectionEffReport:
        by_metric: dict[str, int] = {}
        by_area: dict[str, int] = {}
        by_roi: dict[str, int] = {}
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_area[r.area.value] = by_area.get(r.area.value, 0) + 1
            by_roi[r.roi.value] = by_roi.get(r.roi.value, 0) + 1
        total = len(self._records)
        avg_imp = (
            round(
                sum(r.improvement_pct for r in self._records) / total,
                2,
            )
            if total
            else 0.0
        )
        neg_ct = by_roi.get(ROI.NEGATIVE.value, 0)
        recs: list[str] = []
        if neg_ct > 0:
            recs.append(f"{neg_ct} reflection(s) with negative ROI")
        if avg_imp < 0 and total > 0:
            recs.append("Negative avg improvement — review reflection process")
        low_ct = by_roi.get(ROI.LOW.value, 0)
        if low_ct > total * 0.5 and total > 0:
            recs.append("Majority low ROI — optimize reflection cycles")
        if not recs:
            recs.append("Reflection effectiveness is healthy")
        return ReflectionEffReport(
            total_records=total,
            by_metric=by_metric,
            by_area=by_area,
            by_roi=by_roi,
            avg_improvement_pct=avg_imp,
            negative_roi_count=neg_ct,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        roi_dist: dict[str, int] = {}
        for r in self._records:
            key = r.roi.value
            roi_dist[key] = roi_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "roi_distribution": roi_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("reflection_effectiveness.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def measure_reflection_roi(
        self,
        agent_id: str,
        metric: ReflectionMetric = (ReflectionMetric.MISTAKE_REDUCTION),
        area: ImprovementArea = (ImprovementArea.DETECTION),
        before_value: float = 0.0,
        after_value: float = 0.0,
        time_invested_seconds: float = 0.0,
    ) -> dict[str, Any]:
        """Measure ROI of a reflection cycle."""
        record = self.add_record(
            agent_id=agent_id,
            metric=metric,
            area=area,
            before_value=before_value,
            after_value=after_value,
            time_invested_seconds=(time_invested_seconds),
        )
        return {
            "record_id": record.id,
            "agent_id": agent_id,
            "metric": metric.value,
            "area": area.value,
            "roi": record.roi.value,
            "improvement_pct": record.improvement_pct,
        }

    def track_mistake_reduction(
        self,
        agent_id: str,
        window: int = 20,
    ) -> dict[str, Any]:
        """Track mistake reduction over time."""
        items = [
            r
            for r in self._records
            if r.agent_id == agent_id and r.metric == ReflectionMetric.MISTAKE_REDUCTION
        ]
        recent = items[-window:]
        if len(recent) < 2:
            return {
                "agent_id": agent_id,
                "sufficient_data": False,
                "count": len(recent),
            }
        improvements = [r.improvement_pct for r in recent]
        avg = round(
            sum(improvements) / len(improvements),
            2,
        )
        trend = round(improvements[-1] - improvements[0], 2)
        return {
            "agent_id": agent_id,
            "sufficient_data": True,
            "avg_reduction_pct": avg,
            "trend": trend,
            "improving": trend > 0,
            "sample_count": len(recent),
        }

    def quantify_improvements(
        self,
        area: ImprovementArea | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Quantify improvements across agents."""
        targets = self._records
        if area:
            targets = [r for r in targets if r.area == area]
        agent_data: dict[str, list[float]] = {}
        for r in targets:
            agent_data.setdefault(r.agent_id, []).append(r.improvement_pct)
        results: list[dict[str, Any]] = []
        for agent_id, imps in agent_data.items():
            avg = round(sum(imps) / len(imps), 2)
            results.append(
                {
                    "agent_id": agent_id,
                    "area": (area.value if area else "all"),
                    "avg_improvement_pct": avg,
                    "total_reflections": len(imps),
                    "positive_count": sum(1 for i in imps if i > 0),
                    "negative_count": sum(1 for i in imps if i < 0),
                }
            )
        results.sort(
            key=lambda x: x["avg_improvement_pct"],
            reverse=True,
        )
        return results[:limit]
