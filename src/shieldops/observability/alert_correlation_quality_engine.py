"""AlertCorrelationQualityEngine — Track and analyze alert correlation quality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CorrelationMethod(StrEnum):
    TEMPORAL = "temporal"
    CAUSAL = "causal"
    GRAPH = "graph"
    ML_CLUSTER = "ml_cluster"
    RULE_BASED = "rule_based"


class CorrelationAccuracy(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    UNVERIFIED = "unverified"


class NoiseReduction(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    MODERATE = "moderate"
    POOR = "poor"
    NONE = "none"


# --- Models ---


class AlertCorrelationQualityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_method: CorrelationMethod = CorrelationMethod.TEMPORAL
    correlation_accuracy: CorrelationAccuracy = CorrelationAccuracy.TRUE_POSITIVE
    noise_reduction: NoiseReduction = NoiseReduction.GOOD
    score: float = 0.0
    alerts_correlated: int = 0
    correlation_time_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AlertCorrelationQualityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_method: CorrelationMethod = CorrelationMethod.TEMPORAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AlertCorrelationQualityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_correlation_method: dict[str, int] = Field(default_factory=dict)
    by_correlation_accuracy: dict[str, int] = Field(default_factory=dict)
    by_noise_reduction: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AlertCorrelationQualityEngine:
    """Track and analyze alert correlation quality and noise reduction."""

    def __init__(
        self,
        max_records: int = 200000,
        precision_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = precision_threshold
        self._records: list[AlertCorrelationQualityRecord] = []
        self._analyses: list[AlertCorrelationQualityAnalysis] = []
        logger.info(
            "alert_correlation_quality_engine.initialized",
            max_records=max_records,
            precision_threshold=precision_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        correlation_method: CorrelationMethod = CorrelationMethod.TEMPORAL,
        correlation_accuracy: CorrelationAccuracy = CorrelationAccuracy.TRUE_POSITIVE,
        noise_reduction: NoiseReduction = NoiseReduction.GOOD,
        score: float = 0.0,
        alerts_correlated: int = 0,
        correlation_time_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AlertCorrelationQualityRecord:
        record = AlertCorrelationQualityRecord(
            name=name,
            correlation_method=correlation_method,
            correlation_accuracy=correlation_accuracy,
            noise_reduction=noise_reduction,
            score=score,
            alerts_correlated=alerts_correlated,
            correlation_time_ms=correlation_time_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "alert_correlation_quality_engine.record_added",
            record_id=record.id,
            name=name,
            correlation_method=correlation_method.value,
            correlation_accuracy=correlation_accuracy.value,
        )
        return record

    def get_record(self, record_id: str) -> AlertCorrelationQualityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        correlation_method: CorrelationMethod | None = None,
        correlation_accuracy: CorrelationAccuracy | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AlertCorrelationQualityRecord]:
        results = list(self._records)
        if correlation_method is not None:
            results = [
                r for r in results if r.correlation_method == correlation_method
            ]
        if correlation_accuracy is not None:
            results = [
                r
                for r in results
                if r.correlation_accuracy == correlation_accuracy
            ]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        correlation_method: CorrelationMethod = CorrelationMethod.TEMPORAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AlertCorrelationQualityAnalysis:
        analysis = AlertCorrelationQualityAnalysis(
            name=name,
            correlation_method=correlation_method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "alert_correlation_quality_engine.analysis_added",
            name=name,
            correlation_method=correlation_method.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_precision_recall(self) -> list[dict[str, Any]]:
        """Compute precision and recall per correlation method."""
        method_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            m = r.correlation_method.value
            method_data.setdefault(m, {})
            a = r.correlation_accuracy.value
            method_data[m][a] = method_data[m].get(a, 0) + 1
        results: list[dict[str, Any]] = []
        for method, counts in method_data.items():
            tp = counts.get("true_positive", 0)
            fp = counts.get("false_positive", 0)
            fn = counts.get("false_negative", 0)
            precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) else 0.0
            recall = round(tp / (tp + fn) * 100, 1) if (tp + fn) else 0.0
            f1 = (
                round(2 * precision * recall / (precision + recall), 1)
                if (precision + recall)
                else 0.0
            )
            results.append(
                {
                    "method": method,
                    "true_positives": tp,
                    "false_positives": fp,
                    "false_negatives": fn,
                    "precision_pct": precision,
                    "recall_pct": recall,
                    "f1_score": f1,
                }
            )
        return sorted(results, key=lambda x: x["f1_score"], reverse=True)

    def compute_noise_reduction_effectiveness(self) -> list[dict[str, Any]]:
        """Compute noise reduction effectiveness per method."""
        method_records: dict[str, list[AlertCorrelationQualityRecord]] = {}
        for r in self._records:
            method_records.setdefault(r.correlation_method.value, []).append(r)
        results: list[dict[str, Any]] = []
        for method, records in method_records.items():
            total = len(records)
            good_noise = sum(
                1
                for r in records
                if r.noise_reduction
                in (NoiseReduction.EXCELLENT, NoiseReduction.GOOD)
            )
            effectiveness = round(good_noise / total * 100, 1) if total else 0.0
            avg_correlated = (
                round(
                    sum(r.alerts_correlated for r in records) / total, 2
                )
                if total
                else 0.0
            )
            results.append(
                {
                    "method": method,
                    "total_correlations": total,
                    "effective": good_noise,
                    "effectiveness_pct": effectiveness,
                    "avg_alerts_correlated": avg_correlated,
                }
            )
        return sorted(results, key=lambda x: x["effectiveness_pct"])

    def recommend_correlation_improvements(self) -> list[dict[str, Any]]:
        """Recommend improvements based on correlation accuracy."""
        recommendations: list[dict[str, Any]] = []
        false_pos = [
            r
            for r in self._records
            if r.correlation_accuracy == CorrelationAccuracy.FALSE_POSITIVE
        ]
        for r in false_pos:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "method": r.correlation_method.value,
                    "issue": "false_positive",
                    "priority": "high",
                    "suggestion": (
                        f"Tune {r.correlation_method.value} correlation "
                        f"— false positive on '{r.name}'"
                    ),
                }
            )
        false_neg = [
            r
            for r in self._records
            if r.correlation_accuracy == CorrelationAccuracy.FALSE_NEGATIVE
        ]
        for r in false_neg:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "method": r.correlation_method.value,
                    "issue": "false_negative",
                    "priority": "critical",
                    "suggestion": (
                        f"Missed correlation for '{r.name}' "
                        f"— add detection rule"
                    ),
                }
            )
        poor_noise = [
            r
            for r in self._records
            if r.noise_reduction in (NoiseReduction.POOR, NoiseReduction.NONE)
        ]
        for r in poor_noise:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "method": r.correlation_method.value,
                    "issue": "poor_noise_reduction",
                    "priority": "medium",
                    "suggestion": (
                        f"Improve noise reduction for "
                        f"{r.correlation_method.value}"
                    ),
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(
            recommendations, key=lambda x: priority_order.get(x["priority"], 3)
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        method_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.correlation_method.value
            method_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in method_data.items():
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
                        "correlation_method": r.correlation_method.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [
            r for r in self._records if r.name == key or r.service == key
        ]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(
                1 for s in scores if s < self._threshold
            ),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> AlertCorrelationQualityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.correlation_method.value] = (
                by_e1.get(r.correlation_method.value, 0) + 1
            )
            by_e2[r.correlation_accuracy.value] = (
                by_e2.get(r.correlation_accuracy.value, 0) + 1
            )
            by_e3[r.noise_reduction.value] = (
                by_e3.get(r.noise_reduction.value, 0) + 1
            )
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(
                f"{gap_count} item(s) below threshold ({self._threshold})"
            )
        if self._records and avg_score < self._threshold:
            recs.append(
                f"Avg score {avg_score} below threshold ({self._threshold})"
            )
        if not recs:
            recs.append("Alert Correlation Quality Engine is healthy")
        return AlertCorrelationQualityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_correlation_method=by_e1,
            by_correlation_accuracy=by_e2,
            by_noise_reduction=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("alert_correlation_quality_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.correlation_method.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "correlation_method_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
