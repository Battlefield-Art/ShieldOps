"""Security Anomaly Detector — statistical anomaly detection for security events."""

from __future__ import annotations

import math
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AnomalyType(StrEnum):
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    VOLUMETRIC = "volumetric"


class DetectionAlgorithm(StrEnum):
    ZSCORE = "zscore"
    ISOLATION_FOREST = "isolation_forest"
    DBSCAN = "dbscan"


class AnomalyStatus(StrEnum):
    CONFIRMED = "confirmed"
    INVESTIGATING = "investigating"
    DISMISSED = "dismissed"


# --- Models ---


class SecurityAnomalyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    anomaly_type: AnomalyType = AnomalyType.STATISTICAL
    detection_algorithm: DetectionAlgorithm = DetectionAlgorithm.ZSCORE
    anomaly_status: AnomalyStatus = AnomalyStatus.INVESTIGATING
    score: float = 0.0
    deviation: float = 0.0
    baseline_value: float = 0.0
    observed_value: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SecurityAnomalyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    anomaly_type: AnomalyType = AnomalyType.STATISTICAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SecurityAnomalyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_anomaly_type: dict[str, int] = Field(default_factory=dict)
    by_detection_algorithm: dict[str, int] = Field(default_factory=dict)
    by_anomaly_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SecurityAnomalyDetectorEngine:
    """Statistical anomaly detection for security events."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SecurityAnomalyRecord] = []
        self._analyses: list[SecurityAnomalyAnalysis] = []
        logger.info(
            "security_anomaly_detector.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        anomaly_type: AnomalyType = (AnomalyType.STATISTICAL),
        detection_algorithm: DetectionAlgorithm = (DetectionAlgorithm.ZSCORE),
        anomaly_status: AnomalyStatus = (AnomalyStatus.INVESTIGATING),
        score: float = 0.0,
        deviation: float = 0.0,
        baseline_value: float = 0.0,
        observed_value: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> SecurityAnomalyRecord:
        record = SecurityAnomalyRecord(
            name=name,
            anomaly_type=anomaly_type,
            detection_algorithm=detection_algorithm,
            anomaly_status=anomaly_status,
            score=score,
            deviation=deviation,
            baseline_value=baseline_value,
            observed_value=observed_value,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "security_anomaly_detector.record_added",
            record_id=record.id,
            name=name,
            anomaly_type=anomaly_type.value,
        )
        return record

    def get_record(self, record_id: str) -> SecurityAnomalyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        anomaly_type: AnomalyType | None = None,
        anomaly_status: (AnomalyStatus | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SecurityAnomalyRecord]:
        results = list(self._records)
        if anomaly_type is not None:
            results = [r for r in results if r.anomaly_type == anomaly_type]
        if anomaly_status is not None:
            results = [r for r in results if r.anomaly_status == anomaly_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        anomaly_type: AnomalyType = (AnomalyType.STATISTICAL),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SecurityAnomalyAnalysis:
        analysis = SecurityAnomalyAnalysis(
            name=name,
            anomaly_type=anomaly_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "security_anomaly_detector.analysis",
            name=name,
            anomaly_type=anomaly_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def detect_statistical_anomaly(
        self,
    ) -> list[dict[str, Any]]:
        """Detect statistical anomalies using z-score."""
        svc_data: dict[str, list[SecurityAnomalyRecord]] = {}
        for r in self._records:
            if r.service:
                svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            values = [r.observed_value for r in records]
            if len(values) < 2:
                continue
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = math.sqrt(variance) if variance else 1.0
            anomalies = []
            for r in records:
                z = abs((r.observed_value - mean) / std)
                if z > 2.0:
                    anomalies.append(
                        {
                            "record_id": r.id,
                            "z_score": round(z, 2),
                            "value": r.observed_value,
                        }
                    )
            results.append(
                {
                    "service": svc,
                    "mean": round(mean, 2),
                    "std_dev": round(std, 2),
                    "anomaly_count": len(anomalies),
                    "anomalies": anomalies[:10],
                }
            )
        return sorted(
            results,
            key=lambda x: x["anomaly_count"],
            reverse=True,
        )

    def compute_baseline(
        self,
    ) -> dict[str, Any]:
        """Compute baseline values per service."""
        svc_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.service:
                svc_data.setdefault(r.service, []).append(r.observed_value)
        baselines: dict[str, Any] = {}
        for svc, values in svc_data.items():
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            baselines[svc] = {
                "mean": round(mean, 2),
                "std_dev": round(math.sqrt(variance), 2),
                "sample_count": len(values),
                "min": round(min(values), 2),
                "max": round(max(values), 2),
            }
        return {
            "baselines": baselines,
            "service_count": len(baselines),
        }

    def score_deviation(
        self,
    ) -> list[dict[str, Any]]:
        """Score deviation severity per record."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.baseline_value > 0:
                pct_dev = abs(r.observed_value - r.baseline_value) / r.baseline_value * 100
            else:
                pct_dev = abs(r.deviation) * 100
            severity = (
                "critical"
                if pct_dev > 200
                else ("high" if pct_dev > 100 else ("medium" if pct_dev > 50 else "low"))
            )
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "pct_deviation": round(pct_dev, 1),
                    "severity": severity,
                    "status": (r.anomaly_status.value),
                }
            )
        return sorted(
            results,
            key=lambda x: x["pct_deviation"],
            reverse=True,
        )

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.anomaly_type.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "anomaly_type": (r.anomaly_type.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ---

    def generate_report(
        self,
    ) -> SecurityAnomalyReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.anomaly_type.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.detection_algorithm.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.anomaly_status.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Security Anomaly Detector healthy")
        return SecurityAnomalyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_anomaly_type=by_e1,
            by_detection_algorithm=by_e2,
            by_anomaly_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("security_anomaly_detector.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.anomaly_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "anomaly_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
