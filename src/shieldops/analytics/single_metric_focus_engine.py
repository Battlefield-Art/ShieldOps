"""Single Metric Focus Engine —
track metric trajectory, detect distractions,
and evaluate plateau breakouts."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FocusMetric(StrEnum):
    ACCURACY = "accuracy"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    COST_EFFICIENCY = "cost_efficiency"


class MetricTrend(StrEnum):
    IMPROVING = "improving"
    PLATEAU = "plateau"
    DECLINING = "declining"
    OSCILLATING = "oscillating"


class DistractionType(StrEnum):
    SECONDARY_METRIC = "secondary_metric"
    VANITY_METRIC = "vanity_metric"
    CORRELATED_METRIC = "correlated_metric"
    IRRELEVANT_METRIC = "irrelevant_metric"


# --- Models ---


class SingleMetricRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    focus_metric: FocusMetric = FocusMetric.ACCURACY
    trend: MetricTrend = MetricTrend.IMPROVING
    distraction_type: DistractionType = DistractionType.SECONDARY_METRIC
    metric_value: float = 0.0
    baseline_value: float = 0.0
    is_primary: bool = True
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SingleMetricAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    trend: MetricTrend = MetricTrend.IMPROVING
    plateau_detected: bool = False
    breakout_likely: bool = False
    improvement_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SingleMetricReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_focus_metric: dict[str, int] = Field(default_factory=dict)
    by_trend: dict[str, int] = Field(default_factory=dict)
    by_distraction: dict[str, int] = Field(default_factory=dict)
    top_improving: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SingleMetricFocusEngine:
    """Track metric trajectory, detect distractions,
    and evaluate plateau breakouts."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SingleMetricRecord] = []
        self._analyses: dict[str, SingleMetricAnalysis] = {}
        logger.info(
            "single_metric_focus.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        focus_metric: FocusMetric = FocusMetric.ACCURACY,
        trend: MetricTrend = MetricTrend.IMPROVING,
        distraction_type: DistractionType = DistractionType.SECONDARY_METRIC,
        metric_value: float = 0.0,
        baseline_value: float = 0.0,
        is_primary: bool = True,
        description: str = "",
    ) -> SingleMetricRecord:
        record = SingleMetricRecord(
            experiment_id=experiment_id,
            focus_metric=focus_metric,
            trend=trend,
            distraction_type=distraction_type,
            metric_value=metric_value,
            baseline_value=baseline_value,
            is_primary=is_primary,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "single_metric.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> SingleMetricAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        exp_recs = [
            r for r in self._records if r.experiment_id == rec.experiment_id and r.is_primary
        ]
        plateau = rec.trend == MetricTrend.PLATEAU
        vals = [r.metric_value for r in exp_recs]
        improvement_pct = 0.0
        if rec.baseline_value != 0:
            improvement_pct = round(
                (rec.metric_value - rec.baseline_value) / abs(rec.baseline_value) * 100.0, 2
            )
        breakout_likely = False
        if plateau and len(vals) >= 3:
            recent = vals[-3:]
            spread = max(recent) - min(recent)
            breakout_likely = spread > 0.05 * abs(sum(recent) / len(recent))
        analysis = SingleMetricAnalysis(
            experiment_id=rec.experiment_id,
            trend=rec.trend,
            plateau_detected=plateau,
            breakout_likely=breakout_likely,
            improvement_pct=improvement_pct,
            description=(
                f"Experiment {rec.experiment_id} {rec.focus_metric.value} {improvement_pct}%"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SingleMetricReport:
        by_fm: dict[str, int] = {}
        by_tr: dict[str, int] = {}
        by_dt: dict[str, int] = {}
        for r in self._records:
            by_fm[r.focus_metric.value] = by_fm.get(r.focus_metric.value, 0) + 1
            by_tr[r.trend.value] = by_tr.get(r.trend.value, 0) + 1
            by_dt[r.distraction_type.value] = by_dt.get(r.distraction_type.value, 0) + 1
        exp_improvements: dict[str, float] = {}
        for r in self._records:
            if r.baseline_value != 0 and r.is_primary:
                delta = (r.metric_value - r.baseline_value) / abs(r.baseline_value)
                if (
                    r.experiment_id not in exp_improvements
                    or delta > exp_improvements[r.experiment_id]
                ):
                    exp_improvements[r.experiment_id] = delta
        top_improving = sorted(exp_improvements, key=lambda x: exp_improvements[x], reverse=True)[
            :10
        ]
        recs_list: list[str] = []
        plateaus = by_tr.get("plateau", 0)
        if plateaus > 0:
            recs_list.append(f"{plateaus} metrics in plateau — consider exploration")
        declining = by_tr.get("declining", 0)
        if declining > 0:
            recs_list.append(f"{declining} declining metrics detected")
        if not recs_list:
            recs_list.append("Metric focus is healthy")
        return SingleMetricReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_focus_metric=by_fm,
            by_trend=by_tr,
            by_distraction=by_dt,
            top_improving=top_improving,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        fm_dist: dict[str, int] = {}
        for r in self._records:
            fm_dist[r.focus_metric.value] = fm_dist.get(r.focus_metric.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "focus_metric_distribution": fm_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("single_metric_focus.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def track_metric_trajectory(self, experiment_id: str) -> dict[str, Any]:
        """Track trajectory of the primary metric over time."""
        primary_recs = [
            r for r in self._records if r.experiment_id == experiment_id and r.is_primary
        ]
        if not primary_recs:
            return {"experiment_id": experiment_id, "trajectory": []}
        primary_recs_sorted = sorted(primary_recs, key=lambda x: x.created_at)
        vals = [r.metric_value for r in primary_recs_sorted]
        trajectory: list[dict[str, Any]] = []
        for i, r in enumerate(primary_recs_sorted):
            delta = vals[i] - vals[i - 1] if i > 0 else 0.0
            trajectory.append(
                {
                    "index": i,
                    "value": r.metric_value,
                    "delta": round(delta, 6),
                    "trend": r.trend.value,
                    "timestamp": r.created_at,
                }
            )
        overall_trend = "improving"
        if len(vals) >= 2:
            if vals[-1] > vals[0] * 1.01:
                overall_trend = "improving"
            elif vals[-1] < vals[0] * 0.99:
                overall_trend = "declining"
            else:
                overall_trend = "plateau"
        return {
            "experiment_id": experiment_id,
            "trajectory": trajectory,
            "overall_trend": overall_trend,
            "data_points": len(trajectory),
        }

    def detect_metric_distractions(self) -> list[dict[str, Any]]:
        """Identify non-primary metrics consuming measurement bandwidth."""
        distraction_counts: dict[str, dict[str, Any]] = {}
        for r in self._records:
            if not r.is_primary:
                eid = r.experiment_id
                if eid not in distraction_counts:
                    distraction_counts[eid] = {"count": 0, "types": set()}
                distraction_counts[eid]["count"] += 1
                distraction_counts[eid]["types"].add(r.distraction_type.value)
        primary_counts: dict[str, int] = {}
        for r in self._records:
            if r.is_primary:
                primary_counts[r.experiment_id] = primary_counts.get(r.experiment_id, 0) + 1
        results: list[dict[str, Any]] = []
        for eid, data in distraction_counts.items():
            primary = primary_counts.get(eid, 0)
            ratio = data["count"] / max(primary, 1)
            results.append(
                {
                    "experiment_id": eid,
                    "distraction_count": data["count"],
                    "distraction_types": sorted(data["types"]),
                    "primary_count": primary,
                    "distraction_ratio": round(ratio, 4),
                    "severity": "high" if ratio > 2.0 else "medium" if ratio > 1.0 else "low",
                }
            )
        results.sort(key=lambda x: x["distraction_ratio"], reverse=True)
        return results

    def evaluate_plateau_breakout(self, experiment_id: str) -> dict[str, Any]:
        """Evaluate whether a plateau is likely to break out."""
        primary_recs = [
            r
            for r in self._records
            if r.experiment_id == experiment_id and r.is_primary and r.trend == MetricTrend.PLATEAU
        ]
        if not primary_recs:
            return {"experiment_id": experiment_id, "plateau_detected": False}
        vals = [r.metric_value for r in primary_recs]
        mean_val = sum(vals) / len(vals)
        variance = sum((v - mean_val) ** 2 for v in vals) / len(vals)
        std_val = variance**0.5
        coefficient_of_variation = std_val / abs(mean_val) if mean_val != 0 else 0.0
        breakout_likely = coefficient_of_variation > 0.05
        trend_signal = "breakout_likely" if breakout_likely else "stable_plateau"
        return {
            "experiment_id": experiment_id,
            "plateau_detected": True,
            "mean_value": round(mean_val, 6),
            "std_dev": round(std_val, 6),
            "coefficient_of_variation": round(coefficient_of_variation, 4),
            "breakout_likely": breakout_likely,
            "signal": trend_signal,
            "plateau_records": len(primary_recs),
        }
