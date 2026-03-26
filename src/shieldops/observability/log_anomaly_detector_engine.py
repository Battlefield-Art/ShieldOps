"""Log Anomaly Detector Engine — track log anomaly detection accuracy."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AnomalyMethod(StrEnum):
    STATISTICAL = "statistical"
    PATTERN_MATCH = "pattern_match"
    ML_CLUSTERING = "ml_clustering"
    FREQUENCY = "frequency"
    KEYWORD = "keyword"


class LogCategory(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    SECURITY = "security"
    PERFORMANCE = "performance"
    AUDIT = "audit"


class DetectionOutcome(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    UNVERIFIED = "unverified"


# --- Models ---


class LogAnomalyDetectorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    anomaly_method: AnomalyMethod = AnomalyMethod.STATISTICAL
    log_category: LogCategory = LogCategory.ERROR
    detection_outcome: DetectionOutcome = DetectionOutcome.UNVERIFIED
    confidence_score: float = 0.0
    log_volume: int = 0
    anomaly_count: int = 0
    latency_ms: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogAnomalyDetectorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    anomaly_method: AnomalyMethod = AnomalyMethod.STATISTICAL
    precision: float = 0.0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogAnomalyDetectorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_precision: float = 0.0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    high_false_positive_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LogAnomalyDetectorEngine:
    """Track log anomaly detection accuracy across services."""

    def __init__(
        self,
        max_records: int = 200000,
        precision_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._precision_threshold = precision_threshold
        self._records: list[LogAnomalyDetectorRecord] = []
        self._analyses: dict[str, LogAnomalyDetectorAnalysis] = {}
        logger.info(
            "log_anomaly_detector_engine.init",
            max_records=max_records,
            precision_threshold=precision_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        anomaly_method: AnomalyMethod = AnomalyMethod.STATISTICAL,
        log_category: LogCategory = LogCategory.ERROR,
        detection_outcome: DetectionOutcome = DetectionOutcome.UNVERIFIED,
        confidence_score: float = 0.0,
        log_volume: int = 0,
        anomaly_count: int = 0,
        latency_ms: float = 0.0,
        description: str = "",
    ) -> LogAnomalyDetectorRecord:
        record = LogAnomalyDetectorRecord(
            service_id=service_id,
            anomaly_method=anomaly_method,
            log_category=log_category,
            detection_outcome=detection_outcome,
            confidence_score=confidence_score,
            log_volume=log_volume,
            anomaly_count=anomaly_count,
            latency_ms=latency_ms,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "log_anomaly_detector_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(
        self, key: str,
    ) -> LogAnomalyDetectorAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        svc_recs = [
            r for r in self._records if r.service_id == rec.service_id
        ]
        tp = sum(
            1
            for r in svc_recs
            if r.detection_outcome == DetectionOutcome.TRUE_POSITIVE
        )
        fp = sum(
            1
            for r in svc_recs
            if r.detection_outcome == DetectionOutcome.FALSE_POSITIVE
        )
        precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0.0
        analysis = LogAnomalyDetectorAnalysis(
            service_id=rec.service_id,
            analysis_score=precision,
            anomaly_method=rec.anomaly_method,
            precision=precision,
            data_points=len(svc_recs),
            description=(
                f"Anomaly detection precision {precision}%"
                f" for {rec.service_id}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> LogAnomalyDetectorReport:
        by_m: dict[str, int] = {}
        by_c: dict[str, int] = {}
        by_o: dict[str, int] = {}
        for r in self._records:
            by_m[r.anomaly_method.value] = (
                by_m.get(r.anomaly_method.value, 0) + 1
            )
            by_c[r.log_category.value] = (
                by_c.get(r.log_category.value, 0) + 1
            )
            by_o[r.detection_outcome.value] = (
                by_o.get(r.detection_outcome.value, 0) + 1
            )
        tp = by_o.get(DetectionOutcome.TRUE_POSITIVE.value, 0)
        fp = by_o.get(DetectionOutcome.FALSE_POSITIVE.value, 0)
        precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0.0
        # Find services with high false positive rates
        svc_fp: dict[str, int] = {}
        svc_total: dict[str, int] = {}
        for r in self._records:
            svc_total[r.service_id] = svc_total.get(r.service_id, 0) + 1
            if r.detection_outcome == DetectionOutcome.FALSE_POSITIVE:
                svc_fp[r.service_id] = svc_fp.get(r.service_id, 0) + 1
        high_fp = [
            sid
            for sid, cnt in svc_fp.items()
            if svc_total.get(sid, 1) > 0
            and (cnt / svc_total[sid] * 100) > 30
        ][:10]
        recs: list[str] = []
        if precision < self._precision_threshold:
            recs.append(
                f"Overall precision {precision}% below threshold"
                f" {self._precision_threshold}%"
            )
        if high_fp:
            recs.append(
                f"{len(high_fp)} services with >30% false positive rate"
            )
        if not recs:
            recs.append(
                "Log anomaly detection precision within acceptable range"
            )
        return LogAnomalyDetectorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            overall_precision=precision,
            by_method=by_m,
            by_category=by_c,
            by_outcome=by_o,
            high_false_positive_services=high_fp,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        method_dist: dict[str, int] = {}
        for r in self._records:
            k = r.anomaly_method.value
            method_dist[k] = method_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "precision_threshold": self._precision_threshold,
            "method_distribution": method_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("log_anomaly_detector_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def rank_methods_by_precision(self) -> list[dict[str, Any]]:
        """Rank anomaly detection methods by precision."""
        method_tp: dict[str, int] = {}
        method_fp: dict[str, int] = {}
        for r in self._records:
            k = r.anomaly_method.value
            if r.detection_outcome == DetectionOutcome.TRUE_POSITIVE:
                method_tp[k] = method_tp.get(k, 0) + 1
            elif r.detection_outcome == DetectionOutcome.FALSE_POSITIVE:
                method_fp[k] = method_fp.get(k, 0) + 1
        results: list[dict[str, Any]] = []
        all_methods = set(method_tp.keys()) | set(method_fp.keys())
        for m in all_methods:
            tp = method_tp.get(m, 0)
            fp = method_fp.get(m, 0)
            prec = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0.0
            results.append(
                {
                    "method": m,
                    "precision_pct": prec,
                    "true_positives": tp,
                    "false_positives": fp,
                }
            )
        results.sort(key=lambda x: x["precision_pct"], reverse=True)
        return results

    def compute_detection_latency(self) -> list[dict[str, Any]]:
        """Compute average detection latency per method."""
        method_latencies: dict[str, list[float]] = {}
        for r in self._records:
            if r.latency_ms > 0:
                method_latencies.setdefault(
                    r.anomaly_method.value, []
                ).append(r.latency_ms)
        results: list[dict[str, Any]] = []
        for method, lats in method_latencies.items():
            avg = round(sum(lats) / len(lats), 2)
            results.append(
                {
                    "method": method,
                    "avg_latency_ms": avg,
                    "max_latency_ms": round(max(lats), 2),
                    "sample_count": len(lats),
                }
            )
        results.sort(key=lambda x: x["avg_latency_ms"])
        return results

    def summarize_by_log_category(self) -> list[dict[str, Any]]:
        """Summarize detection outcomes per log category."""
        cat_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            k = r.log_category.value
            cat_data.setdefault(k, {"tp": 0, "fp": 0, "total": 0})
            cat_data[k]["total"] += 1
            if r.detection_outcome == DetectionOutcome.TRUE_POSITIVE:
                cat_data[k]["tp"] += 1
            elif r.detection_outcome == DetectionOutcome.FALSE_POSITIVE:
                cat_data[k]["fp"] += 1
        results: list[dict[str, Any]] = []
        for cat, data in cat_data.items():
            tp_fp = data["tp"] + data["fp"]
            prec = (
                round(data["tp"] / tp_fp * 100, 2) if tp_fp > 0 else 0.0
            )
            results.append(
                {
                    "log_category": cat,
                    "precision_pct": prec,
                    "total_detections": data["total"],
                    "true_positives": data["tp"],
                    "false_positives": data["fp"],
                }
            )
        results.sort(key=lambda x: x["precision_pct"], reverse=True)
        return results
