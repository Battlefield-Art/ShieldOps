"""Hunt Effectiveness Analytics — measure ROI and discovery rates."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HuntMetric(StrEnum):
    DWELL_TIME_REDUCTION = "dwell_time_reduction"
    THREAT_DISCOVERY_RATE = "threat_discovery_rate"
    MEAN_TIME_TO_DETECT = "mean_time_to_detect"
    COVERAGE_IMPROVEMENT = "coverage_improvement"
    ANALYST_EFFICIENCY = "analyst_efficiency"


class EffectivenessScore(StrEnum):
    EXCEPTIONAL = "exceptional"
    ABOVE_AVERAGE = "above_average"
    AVERAGE = "average"
    BELOW_AVERAGE = "below_average"
    INEFFECTIVE = "ineffective"


class ROICategory(StrEnum):
    HIGH_ROI = "high_roi"
    POSITIVE_ROI = "positive_roi"
    NEUTRAL = "neutral"
    NEGATIVE_ROI = "negative_roi"
    UNDETERMINED = "undetermined"


# --- Models ---


class HuntEffectivenessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hunt_id: str = ""
    metric: HuntMetric = HuntMetric.THREAT_DISCOVERY_RATE
    effectiveness: EffectivenessScore = EffectivenessScore.AVERAGE
    roi_category: ROICategory = ROICategory.UNDETERMINED
    value: float = 0.0
    cost_hours: float = 0.0
    threats_found: int = 0
    manual_equivalent_hours: float = 0.0
    created_at: float = Field(default_factory=time.time)


class HuntEffectivenessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    period_days: int = 30
    total_hunts: int = 0
    avg_roi: float = 0.0
    top_metrics: list[str] = Field(default_factory=list)
    analyzed_at: float = Field(default_factory=time.time)


class HuntEffectivenessReport(BaseModel):
    total_records: int = 0
    avg_effectiveness: float = 0.0
    total_threats_found: int = 0
    total_cost_hours: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_effectiveness: dict[str, int] = Field(default_factory=dict)
    by_roi: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class HuntEffectivenessAnalytics:
    """Measure hunt effectiveness, ROI, and discovery rates."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[HuntEffectivenessRecord] = []
        logger.info(
            "hunt_effectiveness_analytics.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> HuntEffectivenessRecord:
        record = HuntEffectivenessRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "hunt_effectiveness_analytics.record_added",
            record_id=record.id,
            hunt_id=record.hunt_id,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "hunt_id": rec.hunt_id,
            "effectiveness": rec.effectiveness.value,
        }

    # -- domain methods --

    def measure_hunt_roi(
        self,
        hunt_id: str,
        cost_hours: float,
        threats_found: int,
        manual_equivalent_hours: float = 0.0,
    ) -> dict[str, Any]:
        """Measure ROI for a specific hunt."""
        if manual_equivalent_hours > 0 and cost_hours > 0:
            roi_ratio = manual_equivalent_hours / cost_hours
        else:
            roi_ratio = 0.0
        if roi_ratio >= 3.0:
            roi_cat = ROICategory.HIGH_ROI
        elif roi_ratio >= 1.5:
            roi_cat = ROICategory.POSITIVE_ROI
        elif roi_ratio >= 0.8:
            roi_cat = ROICategory.NEUTRAL
        else:
            roi_cat = ROICategory.NEGATIVE_ROI
        self.add_record(
            hunt_id=hunt_id,
            metric=HuntMetric.ANALYST_EFFICIENCY,
            roi_category=roi_cat,
            cost_hours=cost_hours,
            threats_found=threats_found,
            manual_equivalent_hours=manual_equivalent_hours,
            value=round(roi_ratio, 4),
        )
        return {
            "hunt_id": hunt_id,
            "roi_ratio": round(roi_ratio, 4),
            "roi_category": roi_cat.value,
            "cost_hours": cost_hours,
            "manual_equivalent_hours": manual_equivalent_hours,
            "threats_found": threats_found,
        }

    def benchmark_vs_manual(self) -> dict[str, Any]:
        """Benchmark automated hunts vs manual equivalents."""
        total_auto = sum(r.cost_hours for r in self._records)
        total_manual = sum(r.manual_equivalent_hours for r in self._records)
        savings = total_manual - total_auto
        pct_savings = round(savings / total_manual * 100, 2) if total_manual > 0 else 0.0
        return {
            "total_automated_hours": round(total_auto, 2),
            "total_manual_equivalent_hours": round(total_manual, 2),
            "hours_saved": round(savings, 2),
            "pct_savings": pct_savings,
            "total_records": len(self._records),
        }

    def track_threat_discovery_rate(self) -> dict[str, Any]:
        """Track the threat discovery rate over time."""
        total_threats = sum(r.threats_found for r in self._records)
        total_hunts = len({r.hunt_id for r in self._records if r.hunt_id})
        rate = round(total_threats / total_hunts, 4) if total_hunts > 0 else 0.0
        return {
            "total_threats_found": total_threats,
            "total_hunts": total_hunts,
            "discovery_rate": rate,
        }

    # -- report / stats --

    def generate_report(self) -> HuntEffectivenessReport:
        by_metric: dict[str, int] = {}
        by_eff: dict[str, int] = {}
        by_roi: dict[str, int] = {}
        total_threats = 0
        total_cost = 0.0
        total_value = 0.0
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_eff[r.effectiveness.value] = by_eff.get(r.effectiveness.value, 0) + 1
            by_roi[r.roi_category.value] = by_roi.get(r.roi_category.value, 0) + 1
            total_threats += r.threats_found
            total_cost += r.cost_hours
            total_value += r.value
        avg_eff = round(total_value / len(self._records), 4) if self._records else 0.0
        recs: list[str] = []
        neg_roi = by_roi.get("negative_roi", 0)
        if neg_roi > 0:
            recs.append(f"{neg_roi} hunt(s) with negative ROI")
        if total_threats == 0 and self._records:
            recs.append("No threats discovered — review hunt strategy")
        if not recs:
            recs.append("Hunt program effective")
        return HuntEffectivenessReport(
            total_records=len(self._records),
            avg_effectiveness=avg_eff,
            total_threats_found=total_threats,
            total_cost_hours=round(total_cost, 2),
            by_metric=by_metric,
            by_effectiveness=by_eff,
            by_roi=by_roi,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "total_threats": sum(r.threats_found for r in self._records),
            "total_cost_hours": round(sum(r.cost_hours for r in self._records), 2),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("hunt_effectiveness_analytics.cleared")
        return {"status": "cleared"}
