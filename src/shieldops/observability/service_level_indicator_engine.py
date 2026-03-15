"""ServiceLevelIndicatorEngine — Track and validate SLI definitions against actual metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SLIType(StrEnum):
    AVAILABILITY = "availability"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"


class SLIStatus(StrEnum):
    MEETING = "meeting"
    AT_RISK = "at_risk"
    BREACHING = "breaching"


class ValidationResult(StrEnum):
    VALID = "valid"
    MISCONFIGURED = "misconfigured"
    STALE = "stale"


# --- Models ---


class ServiceLevelIndicatorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    sli_type: SLIType = SLIType.AVAILABILITY
    sli_status: SLIStatus = SLIStatus.MEETING
    validation_result: ValidationResult = ValidationResult.VALID
    score: float = 0.0
    target_value: float = 99.9
    actual_value: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ServiceLevelIndicatorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    sli_type: SLIType = SLIType.AVAILABILITY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ServiceLevelIndicatorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_sli_type: dict[str, int] = Field(default_factory=dict)
    by_sli_status: dict[str, int] = Field(default_factory=dict)
    by_validation_result: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ServiceLevelIndicatorEngine:
    """Track and validate SLI definitions against actual metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ServiceLevelIndicatorRecord] = []
        self._analyses: list[ServiceLevelIndicatorAnalysis] = []
        logger.info(
            "service_level_indicator_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        sli_type: SLIType = SLIType.AVAILABILITY,
        sli_status: SLIStatus = SLIStatus.MEETING,
        validation_result: ValidationResult = ValidationResult.VALID,
        score: float = 0.0,
        target_value: float = 99.9,
        actual_value: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ServiceLevelIndicatorRecord:
        record = ServiceLevelIndicatorRecord(
            name=name,
            sli_type=sli_type,
            sli_status=sli_status,
            validation_result=validation_result,
            score=score,
            target_value=target_value,
            actual_value=actual_value,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "service_level_indicator_engine.record_added",
            record_id=record.id,
            name=name,
            sli_type=sli_type.value,
            sli_status=sli_status.value,
        )
        return record

    def get_record(self, record_id: str) -> ServiceLevelIndicatorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        sli_type: SLIType | None = None,
        sli_status: SLIStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ServiceLevelIndicatorRecord]:
        results = list(self._records)
        if sli_type is not None:
            results = [r for r in results if r.sli_type == sli_type]
        if sli_status is not None:
            results = [r for r in results if r.sli_status == sli_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        sli_type: SLIType = SLIType.AVAILABILITY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ServiceLevelIndicatorAnalysis:
        analysis = ServiceLevelIndicatorAnalysis(
            name=name,
            sli_type=sli_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "service_level_indicator_engine.analysis_added",
            name=name,
            sli_type=sli_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def validate_sli_definitions(self) -> list[dict[str, Any]]:
        """Validate SLI definitions for correctness and freshness."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            issues: list[str] = []
            if r.validation_result == ValidationResult.MISCONFIGURED:
                issues.append("SLI definition is misconfigured")
            if r.validation_result == ValidationResult.STALE:
                issues.append("SLI definition is stale — needs refresh")
            if r.target_value <= 0:
                issues.append("Invalid target value")
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "sli_type": r.sli_type.value,
                    "validation_result": r.validation_result.value,
                    "issues": issues,
                    "is_valid": len(issues) == 0,
                }
            )
        return results

    def detect_sli_drift(self) -> list[dict[str, Any]]:
        """Detect SLIs drifting away from targets."""
        drifts: list[dict[str, Any]] = []
        for r in self._records:
            if r.target_value > 0:
                drift_pct = round(abs(r.actual_value - r.target_value) / r.target_value * 100, 2)
            else:
                drift_pct = 0.0
            if drift_pct > 5.0 or r.sli_status != SLIStatus.MEETING:
                drifts.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "sli_type": r.sli_type.value,
                        "target": r.target_value,
                        "actual": r.actual_value,
                        "drift_pct": drift_pct,
                        "status": r.sli_status.value,
                    }
                )
        return sorted(drifts, key=lambda x: x["drift_pct"], reverse=True)

    def recommend_sli_improvements(self) -> list[dict[str, Any]]:
        """Recommend improvements for SLI definitions and tracking."""
        recommendations: list[dict[str, Any]] = []
        breaching = [r for r in self._records if r.sli_status == SLIStatus.BREACHING]
        for r in breaching:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "sli_type": r.sli_type.value,
                    "issue": "breaching_sli",
                    "priority": "high",
                    "suggestion": f"SLI {r.name} breaching target — investigate root cause",
                }
            )
        misconfigured = [
            r for r in self._records if r.validation_result == ValidationResult.MISCONFIGURED
        ]
        for r in misconfigured:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "sli_type": r.sli_type.value,
                    "issue": "misconfigured",
                    "priority": "medium",
                    "suggestion": f"Fix misconfigured SLI definition for {r.name}",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.sli_type.value
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
                        "sli_type": r.sli_type.value,
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

    def generate_report(self) -> ServiceLevelIndicatorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.sli_type.value] = by_e1.get(r.sli_type.value, 0) + 1
            by_e2[r.sli_status.value] = by_e2.get(r.sli_status.value, 0) + 1
            by_e3[r.validation_result.value] = by_e3.get(r.validation_result.value, 0) + 1
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
            recs.append("Service Level Indicator Engine is healthy")
        return ServiceLevelIndicatorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_sli_type=by_e1,
            by_sli_status=by_e2,
            by_validation_result=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("service_level_indicator_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.sli_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "sli_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
