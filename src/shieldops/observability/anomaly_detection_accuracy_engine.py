"""Anomaly Detection Accuracy Engine —
measure precision/recall of anomaly detectors,
track false positive rates, tune detection methods."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DetectionMethod(StrEnum):
    STATISTICAL = "statistical"
    ML_CLUSTER = "ml_cluster"
    FORECAST = "forecast"
    THRESHOLD = "threshold"
    HYBRID = "hybrid"


class AnomalyCategory(StrEnum):
    SPIKE = "spike"
    DIP = "dip"
    TREND_CHANGE = "trend_change"
    SEASONAL = "seasonal"
    NOISE = "noise"


class AccuracyOutcome(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    UNVERIFIED = "unverified"


# --- Models ---


class AnomalyDetectionAccuracyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detector_name: str = ""
    metric_name: str = ""
    detection_method: DetectionMethod = DetectionMethod.STATISTICAL
    anomaly_category: AnomalyCategory = AnomalyCategory.SPIKE
    accuracy_outcome: AccuracyOutcome = AccuracyOutcome.UNVERIFIED
    confidence_score: float = 0.0
    detection_latency_ms: float = 0.0
    threshold_value: float = 0.0
    actual_value: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AnomalyDetectionAccuracyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detector_name: str = ""
    detection_method: DetectionMethod = DetectionMethod.STATISTICAL
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AnomalyDetectionAccuracyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_precision: float = 0.0
    by_detection_method: dict[str, int] = Field(default_factory=dict)
    by_anomaly_category: dict[str, int] = Field(default_factory=dict)
    by_accuracy_outcome: dict[str, int] = Field(default_factory=dict)
    low_precision_detectors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AnomalyDetectionAccuracyEngine:
    """Measure precision/recall of anomaly detectors,
    track false positive rates, tune detection methods."""

    def __init__(self, max_records: int = 200000, precision_threshold: float = 85.0) -> None:
        self._max_records = max_records
        self._precision_threshold = precision_threshold
        self._records: list[AnomalyDetectionAccuracyRecord] = []
        self._analyses: dict[str, AnomalyDetectionAccuracyAnalysis] = {}
        logger.info(
            "anomaly_detection_accuracy_engine.init",
            max_records=max_records,
            precision_threshold=precision_threshold,
        )

    def add_record(
        self,
        detector_name: str = "",
        metric_name: str = "",
        detection_method: DetectionMethod = DetectionMethod.STATISTICAL,
        anomaly_category: AnomalyCategory = AnomalyCategory.SPIKE,
        accuracy_outcome: AccuracyOutcome = AccuracyOutcome.UNVERIFIED,
        confidence_score: float = 0.0,
        detection_latency_ms: float = 0.0,
        threshold_value: float = 0.0,
        actual_value: float = 0.0,
        description: str = "",
    ) -> AnomalyDetectionAccuracyRecord:
        record = AnomalyDetectionAccuracyRecord(
            detector_name=detector_name,
            metric_name=metric_name,
            detection_method=detection_method,
            anomaly_category=anomaly_category,
            accuracy_outcome=accuracy_outcome,
            confidence_score=confidence_score,
            detection_latency_ms=detection_latency_ms,
            threshold_value=threshold_value,
            actual_value=actual_value,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "anomaly_detection_accuracy.record_added",
            record_id=record.id,
            detector_name=detector_name,
        )
        return record

    def process(self, key: str) -> AnomalyDetectionAccuracyAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.detector_name == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        tp = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.TRUE_POSITIVE)
        fp = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.FALSE_POSITIVE)
        fn = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.FALSE_NEGATIVE)
        precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn) * 100, 2) if (tp + fn) > 0 else 0.0
        f1 = (
            round(2 * precision * recall / (precision + recall), 2)
            if (precision + recall) > 0
            else 0.0
        )
        fpr = round(fp / len(recs) * 100, 2)
        analysis = AnomalyDetectionAccuracyAnalysis(
            detector_name=recs[0].detector_name,
            detection_method=recs[0].detection_method,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
            description=(
                f"{recs[0].detector_name} precision={precision}% recall={recall}% f1={f1}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> AnomalyDetectionAccuracyReport:
        by_method: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            m = r.detection_method.value
            by_method[m] = by_method.get(m, 0) + 1
            c = r.anomaly_category.value
            by_category[c] = by_category.get(c, 0) + 1
            o = r.accuracy_outcome.value
            by_outcome[o] = by_outcome.get(o, 0) + 1
        precisions: list[float] = [a.precision for a in self._analyses.values()]
        avg_prec = round(sum(precisions) / len(precisions), 2) if precisions else 0.0
        low = [
            a.detector_name
            for a in self._analyses.values()
            if a.precision < self._precision_threshold
        ][:10]
        recs: list[str] = []
        if low:
            recs.append(f"{len(low)} detectors below {self._precision_threshold}% precision")
        fp_count = by_outcome.get("false_positive", 0)
        if fp_count > len(self._records) * 0.2:
            recs.append("High false positive rate — consider tuning thresholds")
        if not recs:
            recs.append("Anomaly detection accuracy within acceptable bounds")
        return AnomalyDetectionAccuracyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_precision=avg_prec,
            by_detection_method=by_method,
            by_anomaly_category=by_category,
            by_accuracy_outcome=by_outcome,
            low_precision_detectors=low,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        outcome_dist: dict[str, int] = {}
        for r in self._records:
            k = r.accuracy_outcome.value
            outcome_dist[k] = outcome_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "outcome_distribution": outcome_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("anomaly_detection_accuracy_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_detector_precision(self) -> list[dict[str, Any]]:
        """Compute precision per detector across all records."""
        det_data: dict[str, list[AnomalyDetectionAccuracyRecord]] = {}
        for r in self._records:
            det_data.setdefault(r.detector_name, []).append(r)
        results: list[dict[str, Any]] = []
        for det, recs in det_data.items():
            tp = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.TRUE_POSITIVE)
            fp = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.FALSE_POSITIVE)
            precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0.0
            results.append(
                {
                    "detector_name": det,
                    "total_detections": len(recs),
                    "true_positives": tp,
                    "false_positives": fp,
                    "precision_pct": precision,
                    "below_threshold": precision < self._precision_threshold,
                }
            )
        results.sort(key=lambda x: x["precision_pct"])
        return results

    def analyze_false_positive_trends(self) -> list[dict[str, Any]]:
        """Analyze false positive trends by detection method."""
        method_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            m = r.detection_method.value
            method_data.setdefault(m, {"total": 0, "fp": 0})
            method_data[m]["total"] += 1
            if r.accuracy_outcome == AccuracyOutcome.FALSE_POSITIVE:
                method_data[m]["fp"] += 1
        results: list[dict[str, Any]] = []
        for method, counts in method_data.items():
            fpr = round(counts["fp"] / counts["total"] * 100, 2) if counts["total"] > 0 else 0.0
            results.append(
                {
                    "detection_method": method,
                    "total": counts["total"],
                    "false_positives": counts["fp"],
                    "false_positive_rate_pct": fpr,
                }
            )
        results.sort(key=lambda x: x["false_positive_rate_pct"], reverse=True)
        return results

    def rank_detectors_by_f1(self) -> list[dict[str, Any]]:
        """Rank detectors by F1 score (harmonic mean of precision and recall)."""
        det_data: dict[str, list[AnomalyDetectionAccuracyRecord]] = {}
        for r in self._records:
            det_data.setdefault(r.detector_name, []).append(r)
        results: list[dict[str, Any]] = []
        for det, recs in det_data.items():
            tp = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.TRUE_POSITIVE)
            fp = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.FALSE_POSITIVE)
            fn = sum(1 for r in recs if r.accuracy_outcome == AccuracyOutcome.FALSE_NEGATIVE)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            results.append(
                {
                    "detector_name": det,
                    "precision": round(prec * 100, 2),
                    "recall": round(rec * 100, 2),
                    "f1_score": round(f1 * 100, 2),
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["f1_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
