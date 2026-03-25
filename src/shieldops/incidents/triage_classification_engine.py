"""Triage Classification Engine — track incident triage classification accuracy."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ClassificationMethod(StrEnum):
    ML_MODEL = "ml_model"
    KEYWORD = "keyword"
    HISTORICAL = "historical"
    MANUAL = "manual"
    LLM_ASSISTED = "llm_assisted"


class SeverityAccuracy(StrEnum):
    EXACT = "exact"
    ONE_OFF = "one_off"
    TWO_OFF = "two_off"
    MISSED = "missed"
    OVERCLASSIFIED = "overclassified"


class TriageOutcome(StrEnum):
    AUTO_RESOLVED = "auto_resolved"
    ESCALATED = "escalated"
    ROUTED = "routed"
    DEDUPLICATED = "deduplicated"
    FALSE_POSITIVE = "false_positive"


# --- Models ---


class TriageClassificationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    classification_method: ClassificationMethod = ClassificationMethod.ML_MODEL
    severity_accuracy: SeverityAccuracy = SeverityAccuracy.EXACT
    triage_outcome: TriageOutcome = TriageOutcome.ROUTED
    predicted_severity: str = ""
    actual_severity: str = ""
    triage_time_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TriageClassificationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    classification_method: ClassificationMethod = ClassificationMethod.ML_MODEL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TriageClassificationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_classification_method: dict[str, int] = Field(default_factory=dict)
    by_severity_accuracy: dict[str, int] = Field(default_factory=dict)
    by_triage_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class TriageClassificationEngine:
    """Triage Classification Engine — track incident triage classification accuracy."""

    def __init__(
        self,
        max_records: int = 200000,
        accuracy_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = accuracy_threshold
        self._records: list[TriageClassificationRecord] = []
        self._analyses: list[TriageClassificationAnalysis] = []
        logger.info(
            "triage_classification_engine.initialized",
            max_records=max_records,
            accuracy_threshold=accuracy_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        incident_id: str,
        classification_method: ClassificationMethod = ClassificationMethod.ML_MODEL,
        severity_accuracy: SeverityAccuracy = SeverityAccuracy.EXACT,
        triage_outcome: TriageOutcome = TriageOutcome.ROUTED,
        predicted_severity: str = "",
        actual_severity: str = "",
        triage_time_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> TriageClassificationRecord:
        record = TriageClassificationRecord(
            incident_id=incident_id,
            classification_method=classification_method,
            severity_accuracy=severity_accuracy,
            triage_outcome=triage_outcome,
            predicted_severity=predicted_severity,
            actual_severity=actual_severity,
            triage_time_ms=triage_time_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "triage_classification_engine.record_added",
            record_id=record.id,
            incident_id=incident_id,
            classification_method=classification_method.value,
            severity_accuracy=severity_accuracy.value,
        )
        return record

    def get_record(self, record_id: str) -> TriageClassificationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        classification_method: ClassificationMethod | None = None,
        severity_accuracy: SeverityAccuracy | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TriageClassificationRecord]:
        results = list(self._records)
        if classification_method is not None:
            results = [r for r in results if r.classification_method == classification_method]
        if severity_accuracy is not None:
            results = [r for r in results if r.severity_accuracy == severity_accuracy]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        classification_method: ClassificationMethod = ClassificationMethod.ML_MODEL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TriageClassificationAnalysis:
        analysis = TriageClassificationAnalysis(
            name=name,
            classification_method=classification_method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "triage_classification_engine.analysis_added",
            name=name,
            classification_method=classification_method.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_classification_accuracy(self) -> dict[str, Any]:
        method_data: dict[str, list[str]] = {}
        for r in self._records:
            key = r.classification_method.value
            method_data.setdefault(key, []).append(r.severity_accuracy.value)
        result: dict[str, Any] = {}
        for k, accs in method_data.items():
            exact = sum(1 for a in accs if a == "exact")
            result[k] = {
                "count": len(accs),
                "exact_pct": round(exact / len(accs) * 100, 2),
            }
        return result

    def identify_misclassifications(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.severity_accuracy in (
                SeverityAccuracy.TWO_OFF,
                SeverityAccuracy.MISSED,
                SeverityAccuracy.OVERCLASSIFIED,
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "incident_id": r.incident_id,
                        "classification_method": r.classification_method.value,
                        "severity_accuracy": r.severity_accuracy.value,
                        "predicted_severity": r.predicted_severity,
                        "actual_severity": r.actual_severity,
                        "triage_time_ms": r.triage_time_ms,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["triage_time_ms"], reverse=True)

    def detect_triage_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TriageClassificationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.classification_method.value] = by_e1.get(r.classification_method.value, 0) + 1
            by_e2[r.severity_accuracy.value] = by_e2.get(r.severity_accuracy.value, 0) + 1
            by_e3[r.triage_outcome.value] = by_e3.get(r.triage_outcome.value, 0) + 1
        exact_count = sum(1 for r in self._records if r.severity_accuracy == SeverityAccuracy.EXACT)
        accuracy_pct = round(exact_count / len(self._records) * 100, 2) if self._records else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.severity_accuracy
            in (
                SeverityAccuracy.TWO_OFF,
                SeverityAccuracy.MISSED,
                SeverityAccuracy.OVERCLASSIFIED,
            )
        )
        gap_list = self.identify_misclassifications()
        top_gaps = [g["incident_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} significant misclassification(s)")
        if self._records and accuracy_pct < self._threshold:
            recs.append(f"Accuracy {accuracy_pct}% below threshold ({self._threshold}%)")
        if not recs:
            recs.append("Triage Classification Engine is healthy")
        return TriageClassificationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=accuracy_pct,
            by_classification_method=by_e1,
            by_severity_accuracy=by_e2,
            by_triage_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("triage_classification_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.classification_method.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "accuracy_threshold": self._threshold,
            "classification_method_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
