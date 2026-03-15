"""PredictiveIncidentEngine — Predict incidents based on historical patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PredictionHorizon(StrEnum):
    MINUTES = "minutes"
    HOURS = "hours"
    DAYS = "days"


class IndicatorType(StrEnum):
    METRIC_ANOMALY = "metric_anomaly"
    LOG_PATTERN = "log_pattern"
    DEPLOYMENT_CHANGE = "deployment_change"
    CAPACITY_TREND = "capacity_trend"


class PredictionConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --- Models ---


class PredictiveIncidentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    horizon: PredictionHorizon = PredictionHorizon.HOURS
    indicator: IndicatorType = IndicatorType.METRIC_ANOMALY
    confidence: PredictionConfidence = PredictionConfidence.MEDIUM
    score: float = 0.0
    prediction_accuracy: float = 0.0
    indicator_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PredictiveIncidentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    horizon: PredictionHorizon = PredictionHorizon.HOURS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PredictiveIncidentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_horizon: dict[str, int] = Field(default_factory=dict)
    by_indicator: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PredictiveIncidentEngine:
    """Predict incidents before they happen based on historical patterns."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PredictiveIncidentRecord] = []
        self._analyses: list[PredictiveIncidentAnalysis] = []
        logger.info(
            "predictive_incident_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        horizon: PredictionHorizon = PredictionHorizon.HOURS,
        indicator: IndicatorType = IndicatorType.METRIC_ANOMALY,
        confidence: PredictionConfidence = PredictionConfidence.MEDIUM,
        score: float = 0.0,
        prediction_accuracy: float = 0.0,
        indicator_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> PredictiveIncidentRecord:
        record = PredictiveIncidentRecord(
            name=name,
            horizon=horizon,
            indicator=indicator,
            confidence=confidence,
            score=score,
            prediction_accuracy=prediction_accuracy,
            indicator_count=indicator_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "predictive_incident_engine.record_added",
            record_id=record.id,
            name=name,
            horizon=horizon.value,
            indicator=indicator.value,
        )
        return record

    def get_record(self, record_id: str) -> PredictiveIncidentRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        horizon: PredictionHorizon | None = None,
        confidence: PredictionConfidence | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PredictiveIncidentRecord]:
        results = list(self._records)
        if horizon is not None:
            results = [r for r in results if r.horizon == horizon]
        if confidence is not None:
            results = [r for r in results if r.confidence == confidence]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        horizon: PredictionHorizon = PredictionHorizon.HOURS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PredictiveIncidentAnalysis:
        analysis = PredictiveIncidentAnalysis(
            name=name,
            horizon=horizon,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "predictive_incident_engine.analysis_added",
            name=name,
            horizon=horizon.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def generate_incident_predictions(self) -> list[dict[str, Any]]:
        """Generate incident predictions based on current indicators."""
        svc_indicators: dict[str, list[PredictiveIncidentRecord]] = {}
        for r in self._records:
            svc_indicators.setdefault(r.service, []).append(r)
        predictions: list[dict[str, Any]] = []
        for svc, records in svc_indicators.items():
            high_conf = [r for r in records if r.confidence == PredictionConfidence.HIGH]
            indicator_types = list({r.indicator.value for r in records})
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            risk_level = (
                "critical"
                if len(high_conf) > 3
                else "high"
                if len(high_conf) > 1
                else "medium"
                if avg_score > 60
                else "low"
            )
            predictions.append(
                {
                    "service": svc,
                    "high_confidence_indicators": len(high_conf),
                    "total_indicators": len(records),
                    "indicator_types": indicator_types,
                    "avg_score": avg_score,
                    "risk_level": risk_level,
                    "predicted_horizon": records[-1].horizon.value if records else "unknown",
                }
            )
        return sorted(
            predictions,
            key=lambda x: (
                0
                if x["risk_level"] == "critical"
                else 1
                if x["risk_level"] == "high"
                else 2
                if x["risk_level"] == "medium"
                else 3
            ),
        )

    def evaluate_prediction_accuracy(self) -> list[dict[str, Any]]:
        """Evaluate prediction accuracy across horizons and indicator types."""
        horizon_data: dict[str, list[float]] = {}
        indicator_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.prediction_accuracy > 0:
                horizon_data.setdefault(r.horizon.value, []).append(r.prediction_accuracy)
                indicator_data.setdefault(r.indicator.value, []).append(r.prediction_accuracy)
        results: list[dict[str, Any]] = []
        for horizon, accs in horizon_data.items():
            avg_acc = round(sum(accs) / len(accs), 2)
            results.append(
                {
                    "dimension": "horizon",
                    "value": horizon,
                    "avg_accuracy": avg_acc,
                    "sample_count": len(accs),
                    "grade": "excellent"
                    if avg_acc >= 90
                    else "good"
                    if avg_acc >= 70
                    else "fair"
                    if avg_acc >= 50
                    else "poor",
                }
            )
        for ind, accs in indicator_data.items():
            avg_acc = round(sum(accs) / len(accs), 2)
            results.append(
                {
                    "dimension": "indicator",
                    "value": ind,
                    "avg_accuracy": avg_acc,
                    "sample_count": len(accs),
                    "grade": "excellent"
                    if avg_acc >= 90
                    else "good"
                    if avg_acc >= 70
                    else "fair"
                    if avg_acc >= 50
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["avg_accuracy"], reverse=True)

    def identify_leading_indicators(self) -> list[dict[str, Any]]:
        """Identify the most reliable leading indicators for incidents."""
        indicator_stats: dict[str, dict[str, Any]] = {}
        for r in self._records:
            key = r.indicator.value
            if key not in indicator_stats:
                indicator_stats[key] = {
                    "total_count": 0,
                    "high_conf_count": 0,
                    "accuracies": [],
                    "services": set(),
                }
            indicator_stats[key]["total_count"] += 1
            if r.confidence == PredictionConfidence.HIGH:
                indicator_stats[key]["high_conf_count"] += 1
            if r.prediction_accuracy > 0:
                indicator_stats[key]["accuracies"].append(r.prediction_accuracy)
            indicator_stats[key]["services"].add(r.service)
        results: list[dict[str, Any]] = []
        for ind, stats in indicator_stats.items():
            accs = stats["accuracies"]
            avg_acc = round(sum(accs) / len(accs), 2) if accs else 0.0
            reliability = (
                round(stats["high_conf_count"] / stats["total_count"] * 100, 1)
                if stats["total_count"] > 0
                else 0.0
            )
            results.append(
                {
                    "indicator": ind,
                    "total_occurrences": stats["total_count"],
                    "high_confidence_pct": reliability,
                    "avg_accuracy": avg_acc,
                    "services_affected": len(stats["services"]),
                    "reliability_grade": "excellent"
                    if reliability >= 80
                    else "good"
                    if reliability >= 60
                    else "fair"
                    if reliability >= 40
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["high_confidence_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.horizon.value
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
                        "horizon": r.horizon.value,
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
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> PredictiveIncidentReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.horizon.value] = by_e1.get(r.horizon.value, 0) + 1
            by_e2[r.indicator.value] = by_e2.get(r.indicator.value, 0) + 1
            by_e3[r.confidence.value] = by_e3.get(r.confidence.value, 0) + 1
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
            recs.append("Predictive Incident Engine is healthy")
        return PredictiveIncidentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_horizon=by_e1,
            by_indicator=by_e2,
            by_confidence=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("predictive_incident_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.horizon.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "horizon_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
