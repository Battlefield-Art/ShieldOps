"""Metric Baseline Engine —
establish dynamic baselines for metrics,
detect deviations, manage seasonal adjustments."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BaselineMethod(StrEnum):
    MOVING_AVG = "moving_avg"
    EXPONENTIAL = "exponential"
    SEASONAL = "seasonal"
    PERCENTILE = "percentile"
    FIXED = "fixed"


class DeviationLevel(StrEnum):
    EXTREME = "extreme"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    WITHIN_NORMAL = "within_normal"


class MetricType(StrEnum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    RATE = "rate"


# --- Models ---


class MetricBaselineRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str = ""
    service_name: str = ""
    baseline_method: BaselineMethod = BaselineMethod.MOVING_AVG
    deviation_level: DeviationLevel = DeviationLevel.WITHIN_NORMAL
    metric_type: MetricType = MetricType.GAUGE
    baseline_value: float = 0.0
    current_value: float = 0.0
    sigma_distance: float = 0.0
    std_deviation: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MetricBaselineAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str = ""
    baseline_method: BaselineMethod = BaselineMethod.MOVING_AVG
    avg_sigma_distance: float = 0.0
    deviation_level: DeviationLevel = DeviationLevel.WITHIN_NORMAL
    anomaly_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MetricBaselineReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_sigma_distance: float = 0.0
    by_baseline_method: dict[str, int] = Field(default_factory=dict)
    by_deviation_level: dict[str, int] = Field(default_factory=dict)
    by_metric_type: dict[str, int] = Field(default_factory=dict)
    high_deviation_metrics: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MetricBaselineEngine:
    """Establish dynamic baselines for metrics,
    detect deviations, manage seasonal adjustments."""

    def __init__(self, max_records: int = 200000, deviation_threshold: float = 3.0) -> None:
        self._max_records = max_records
        self._deviation_threshold = deviation_threshold
        self._records: list[MetricBaselineRecord] = []
        self._analyses: dict[str, MetricBaselineAnalysis] = {}
        logger.info(
            "metric_baseline_engine.init",
            max_records=max_records,
            deviation_threshold=deviation_threshold,
        )

    def add_record(
        self,
        metric_name: str = "",
        service_name: str = "",
        baseline_method: BaselineMethod = BaselineMethod.MOVING_AVG,
        deviation_level: DeviationLevel = DeviationLevel.WITHIN_NORMAL,
        metric_type: MetricType = MetricType.GAUGE,
        baseline_value: float = 0.0,
        current_value: float = 0.0,
        sigma_distance: float = 0.0,
        std_deviation: float = 0.0,
        description: str = "",
    ) -> MetricBaselineRecord:
        record = MetricBaselineRecord(
            metric_name=metric_name,
            service_name=service_name,
            baseline_method=baseline_method,
            deviation_level=deviation_level,
            metric_type=metric_type,
            baseline_value=baseline_value,
            current_value=current_value,
            sigma_distance=sigma_distance,
            std_deviation=std_deviation,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "metric_baseline.record_added",
            record_id=record.id,
            metric_name=metric_name,
        )
        return record

    def process(self, key: str) -> MetricBaselineAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.metric_name == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        avg_sigma = round(sum(r.sigma_distance for r in recs) / len(recs), 2)
        anomaly_count = sum(1 for r in recs if r.sigma_distance >= self._deviation_threshold)
        if avg_sigma >= self._deviation_threshold * 2:
            level = DeviationLevel.EXTREME
        elif avg_sigma >= self._deviation_threshold:
            level = DeviationLevel.HIGH
        elif avg_sigma >= self._deviation_threshold * 0.5:
            level = DeviationLevel.MODERATE
        elif avg_sigma >= 1.0:
            level = DeviationLevel.LOW
        else:
            level = DeviationLevel.WITHIN_NORMAL
        analysis = MetricBaselineAnalysis(
            metric_name=recs[0].metric_name,
            baseline_method=recs[0].baseline_method,
            avg_sigma_distance=avg_sigma,
            deviation_level=level,
            anomaly_count=anomaly_count,
            description=(
                f"{recs[0].metric_name} avg_sigma={avg_sigma} "
                f"level={level.value} anomalies={anomaly_count}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> MetricBaselineReport:
        by_method: dict[str, int] = {}
        by_level: dict[str, int] = {}
        by_type: dict[str, int] = {}
        sigmas: list[float] = []
        for r in self._records:
            m = r.baseline_method.value
            by_method[m] = by_method.get(m, 0) + 1
            lv = r.deviation_level.value
            by_level[lv] = by_level.get(lv, 0) + 1
            mt = r.metric_type.value
            by_type[mt] = by_type.get(mt, 0) + 1
            sigmas.append(r.sigma_distance)
        avg_sigma = round(sum(sigmas) / len(sigmas), 2) if sigmas else 0.0
        high_dev = list(
            {r.metric_name for r in self._records if r.sigma_distance >= self._deviation_threshold}
        )[:10]
        recs: list[str] = []
        if high_dev:
            recs.append(f"{len(high_dev)} metrics exceed {self._deviation_threshold}σ threshold")
        if not recs:
            recs.append("All metrics within baseline deviation bounds")
        return MetricBaselineReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_sigma_distance=avg_sigma,
            by_baseline_method=by_method,
            by_deviation_level=by_level,
            by_metric_type=by_type,
            high_deviation_metrics=high_dev,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        level_dist: dict[str, int] = {}
        for r in self._records:
            k = r.deviation_level.value
            level_dist[k] = level_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "deviation_distribution": level_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("metric_baseline_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_baseline_drift(self) -> list[dict[str, Any]]:
        """Compute baseline drift per metric over recorded observations."""
        metric_data: dict[str, list[MetricBaselineRecord]] = {}
        for r in self._records:
            metric_data.setdefault(r.metric_name, []).append(r)
        results: list[dict[str, Any]] = []
        for metric, recs in metric_data.items():
            avg_baseline = sum(r.baseline_value for r in recs) / len(recs)
            avg_current = sum(r.current_value for r in recs) / len(recs)
            drift_pct = (
                round((avg_current - avg_baseline) / avg_baseline * 100, 2)
                if avg_baseline != 0
                else 0.0
            )
            results.append(
                {
                    "metric_name": metric,
                    "observation_count": len(recs),
                    "avg_baseline": round(avg_baseline, 2),
                    "avg_current": round(avg_current, 2),
                    "drift_pct": drift_pct,
                }
            )
        results.sort(key=lambda x: abs(x["drift_pct"]), reverse=True)
        return results

    def detect_seasonal_anomalies(self) -> list[dict[str, Any]]:
        """Detect anomalies in seasonal baseline metrics."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.baseline_method == BaselineMethod.SEASONAL
                and r.sigma_distance >= self._deviation_threshold
            ):
                results.append(
                    {
                        "metric_name": r.metric_name,
                        "service_name": r.service_name,
                        "sigma_distance": r.sigma_distance,
                        "baseline_value": r.baseline_value,
                        "current_value": r.current_value,
                        "deviation_level": r.deviation_level.value,
                    }
                )
        results.sort(key=lambda x: x["sigma_distance"], reverse=True)
        return results

    def rank_metrics_by_volatility(self) -> list[dict[str, Any]]:
        """Rank metrics by standard deviation volatility."""
        metric_data: dict[str, list[float]] = {}
        for r in self._records:
            metric_data.setdefault(r.metric_name, []).append(r.std_deviation)
        results: list[dict[str, Any]] = []
        for metric, stds in metric_data.items():
            avg_std = round(sum(stds) / len(stds), 4)
            results.append(
                {
                    "metric_name": metric,
                    "sample_count": len(stds),
                    "avg_std_deviation": avg_std,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["avg_std_deviation"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
