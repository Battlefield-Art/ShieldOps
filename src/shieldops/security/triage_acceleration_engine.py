"""Triage Acceleration Engine — AI triage vs manual baselines."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TriageMethod(StrEnum):
    AI_AUTOMATED = "ai_automated"
    AI_ASSISTED = "ai_assisted"
    MANUAL = "manual"
    HYBRID = "hybrid"
    BASELINE = "baseline"


class AccuracyBand(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    FAILING = "failing"


class SpeedupTier(StrEnum):
    EXTREME = "extreme"
    HIGH = "high"
    MODERATE = "moderate"
    MARGINAL = "marginal"
    NONE = "none"


# --- Models ---


class TriageRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str = ""
    method: TriageMethod = TriageMethod.AI_AUTOMATED
    accuracy_band: AccuracyBand = AccuracyBand.GOOD
    speedup_tier: SpeedupTier = SpeedupTier.HIGH
    triage_time_seconds: float = 0.0
    baseline_time_seconds: float = 0.0
    correct: bool = True
    false_positive: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TriageAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str = ""
    method: TriageMethod = TriageMethod.AI_AUTOMATED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TriageReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_speedup: float = 0.0
    accuracy_rate: float = 0.0
    false_positive_rate: float = 0.0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_accuracy: dict[str, int] = Field(default_factory=dict)
    by_speedup: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class TriageAccelerationEngine:
    """Measure AI triage vs manual baselines."""

    def __init__(
        self,
        max_records: int = 200000,
        accuracy_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._accuracy_threshold = accuracy_threshold
        self._records: list[TriageRecord] = []
        self._analyses: list[TriageAnalysis] = []
        logger.info(
            "triage_acceleration_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        alert_id: str = "",
        method: TriageMethod = (TriageMethod.AI_AUTOMATED),
        accuracy_band: AccuracyBand = (AccuracyBand.GOOD),
        speedup_tier: SpeedupTier = (SpeedupTier.HIGH),
        triage_time_seconds: float = 0.0,
        baseline_time_seconds: float = 0.0,
        correct: bool = True,
        false_positive: bool = False,
        service: str = "",
        team: str = "",
    ) -> TriageRecord:
        record = TriageRecord(
            alert_id=alert_id,
            method=method,
            accuracy_band=accuracy_band,
            speedup_tier=speedup_tier,
            triage_time_seconds=(triage_time_seconds),
            baseline_time_seconds=(baseline_time_seconds),
            correct=correct,
            false_positive=false_positive,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "triage_acceleration.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, alert_id: str) -> TriageAnalysis:
        relevant = [r for r in self._records if r.alert_id == alert_id]
        if not relevant:
            analysis = TriageAnalysis(
                alert_id=alert_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        correct = sum(1 for r in relevant if r.correct)
        acc = (correct / len(relevant)) * 100
        breached = acc < self._accuracy_threshold
        analysis = TriageAnalysis(
            alert_id=alert_id,
            analysis_score=round(acc, 2),
            threshold=self._accuracy_threshold,
            breached=breached,
            description=(f"accuracy={round(acc, 2)}%"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def measure_speedup(self) -> dict[str, Any]:
        """Speedup ratio by method."""
        method_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.baseline_time_seconds > 0 and r.triage_time_seconds > 0:
                ratio = r.baseline_time_seconds / r.triage_time_seconds
                method_data.setdefault(r.method.value, []).append(ratio)
        result: dict[str, Any] = {}
        for method, ratios in method_data.items():
            result[method] = {
                "count": len(ratios),
                "avg_speedup": round(sum(ratios) / len(ratios), 2),
            }
        return result

    def track_false_positive_rate(
        self,
    ) -> dict[str, Any]:
        """FP rate by method."""
        method_fp: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.method.value
            method_fp.setdefault(key, {"total": 0, "fp": 0})
            method_fp[key]["total"] += 1
            if r.false_positive:
                method_fp[key]["fp"] += 1
        result: dict[str, Any] = {}
        for method, data in method_fp.items():
            rate = 0.0
            if data["total"] > 0:
                rate = data["fp"] / data["total"] * 100
            result[method] = {
                "total": data["total"],
                "false_positives": data["fp"],
                "fp_rate": round(rate, 2),
            }
        return result

    def benchmark_accuracy(
        self,
    ) -> list[dict[str, Any]]:
        """Accuracy by method, sorted."""
        method_acc: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.method.value
            method_acc.setdefault(
                key,
                {"total": 0, "correct": 0},
            )
            method_acc[key]["total"] += 1
            if r.correct:
                method_acc[key]["correct"] += 1
        results: list[dict[str, Any]] = []
        for method, data in method_acc.items():
            acc = 0.0
            if data["total"] > 0:
                acc = data["correct"] / data["total"] * 100
            results.append(
                {
                    "method": method,
                    "accuracy": round(acc, 2),
                    "total": data["total"],
                }
            )
        return sorted(
            results,
            key=lambda x: x["accuracy"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(self) -> TriageReport:
        by_method: dict[str, int] = {}
        by_acc: dict[str, int] = {}
        by_speed: dict[str, int] = {}
        for r in self._records:
            by_method[r.method.value] = by_method.get(r.method.value, 0) + 1
            by_acc[r.accuracy_band.value] = by_acc.get(r.accuracy_band.value, 0) + 1
            by_speed[r.speedup_tier.value] = by_speed.get(r.speedup_tier.value, 0) + 1
        speedups: list[float] = []
        for r in self._records:
            if r.baseline_time_seconds > 0 and r.triage_time_seconds > 0:
                speedups.append(r.baseline_time_seconds / r.triage_time_seconds)
        avg_sp = round(sum(speedups) / len(speedups), 2) if speedups else 0.0
        correct = sum(1 for r in self._records if r.correct)
        acc_rate = (
            round(
                correct / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        fp = sum(1 for r in self._records if r.false_positive)
        fp_rate = round(fp / len(self._records) * 100, 2) if self._records else 0.0
        recs: list[str] = []
        if acc_rate < self._accuracy_threshold:
            recs.append(f"Accuracy {acc_rate}% below {self._accuracy_threshold}%")
        if fp_rate > 10.0:
            recs.append(f"FP rate {fp_rate}% exceeds 10%")
        if not recs:
            recs.append("Triage acceleration is healthy")
        return TriageReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_speedup=avg_sp,
            accuracy_rate=acc_rate,
            false_positive_rate=fp_rate,
            by_method=by_method,
            by_accuracy=by_acc,
            by_speedup=by_speed,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "accuracy_threshold": (self._accuracy_threshold),
            "unique_alerts": len({r.alert_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("triage_acceleration_engine.cleared")
        return {"status": "cleared"}
