"""LogPipelineQualityEngine — Track log pipeline quality metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LogQualityDimension(StrEnum):
    PARSE_RATE = "parse_rate"
    FORMAT_CONSISTENCY = "format_consistency"
    ENRICHMENT_COVERAGE = "enrichment_coverage"


class QualityGrade(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


class PipelineIssue(StrEnum):
    PARSE_FAILURE = "parse_failure"
    MISSING_FIELDS = "missing_fields"
    FORMAT_MISMATCH = "format_mismatch"


# --- Models ---


class LogPipelineQualityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    dimension: LogQualityDimension = LogQualityDimension.PARSE_RATE
    grade: QualityGrade = QualityGrade.GOOD
    issue: PipelineIssue = PipelineIssue.PARSE_FAILURE
    score: float = 0.0
    record_count: int = 0
    failure_rate: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class LogPipelineQualityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    dimension: LogQualityDimension = LogQualityDimension.PARSE_RATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogPipelineQualityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_dimension: dict[str, int] = Field(default_factory=dict)
    by_grade: dict[str, int] = Field(default_factory=dict)
    by_issue: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class LogPipelineQualityEngine:
    """Track log pipeline quality (parsing success, format consistency, enrichment)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[LogPipelineQualityRecord] = []
        self._analyses: list[LogPipelineQualityAnalysis] = []
        logger.info(
            "log_pipeline_quality_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        dimension: LogQualityDimension = LogQualityDimension.PARSE_RATE,
        grade: QualityGrade = QualityGrade.GOOD,
        issue: PipelineIssue = PipelineIssue.PARSE_FAILURE,
        score: float = 0.0,
        record_count: int = 0,
        failure_rate: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> LogPipelineQualityRecord:
        record = LogPipelineQualityRecord(
            name=name,
            dimension=dimension,
            grade=grade,
            issue=issue,
            score=score,
            record_count=record_count,
            failure_rate=failure_rate,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "log_pipeline_quality_engine.record_added",
            record_id=record.id,
            name=name,
            dimension=dimension.value,
            grade=grade.value,
        )
        return record

    def get_record(self, record_id: str) -> LogPipelineQualityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        dimension: LogQualityDimension | None = None,
        grade: QualityGrade | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[LogPipelineQualityRecord]:
        results = list(self._records)
        if dimension is not None:
            results = [r for r in results if r.dimension == dimension]
        if grade is not None:
            results = [r for r in results if r.grade == grade]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        dimension: LogQualityDimension = LogQualityDimension.PARSE_RATE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> LogPipelineQualityAnalysis:
        analysis = LogPipelineQualityAnalysis(
            name=name,
            dimension=dimension,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "log_pipeline_quality_engine.analysis_added",
            name=name,
            dimension=dimension.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_pipeline_quality_score(self) -> list[dict[str, Any]]:
        """Compute quality scores per service across all dimensions."""
        svc_data: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, {})
            svc_data[r.service].setdefault(r.dimension.value, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, dims in svc_data.items():
            all_scores: list[float] = []
            dim_avgs: dict[str, float] = {}
            for dim, scores in dims.items():
                avg = round(sum(scores) / len(scores), 2)
                dim_avgs[dim] = avg
                all_scores.extend(scores)
            overall = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0.0
            results.append(
                {
                    "service": svc,
                    "overall_score": overall,
                    "dimension_scores": dim_avgs,
                    "grade": "excellent"
                    if overall >= 90
                    else "good"
                    if overall >= 70
                    else "fair"
                    if overall >= 50
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["overall_score"], reverse=True)

    def identify_parsing_failures(self) -> list[dict[str, Any]]:
        """Identify services with high parsing failure rates."""
        failures: list[dict[str, Any]] = []
        for r in self._records:
            if r.issue == PipelineIssue.PARSE_FAILURE and r.failure_rate > 0:
                failures.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "failure_rate": r.failure_rate,
                        "score": r.score,
                        "priority": "high"
                        if r.failure_rate > 0.5
                        else "medium"
                        if r.failure_rate > 0.2
                        else "low",
                    }
                )
        return sorted(failures, key=lambda x: x["failure_rate"], reverse=True)

    def recommend_format_standardization(self) -> list[dict[str, Any]]:
        """Recommend format standardization for inconsistent log sources."""
        recommendations: list[dict[str, Any]] = []
        svc_issues: dict[str, list[LogPipelineQualityRecord]] = {}
        for r in self._records:
            if r.issue in (PipelineIssue.FORMAT_MISMATCH, PipelineIssue.MISSING_FIELDS):
                svc_issues.setdefault(r.service, []).append(r)
        for svc, records in svc_issues.items():
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            recommendations.append(
                {
                    "service": svc,
                    "issue_count": len(records),
                    "avg_score": avg_score,
                    "issues": list({r.issue.value for r in records}),
                    "priority": "high" if avg_score < 30 else "medium" if avg_score < 60 else "low",
                    "suggestion": f"Standardize log format for {svc} ({len(records)} issues)",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1 if x["priority"] == "medium" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.dimension.value
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
                        "dimension": r.dimension.value,
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

    def generate_report(self) -> LogPipelineQualityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.dimension.value] = by_e1.get(r.dimension.value, 0) + 1
            by_e2[r.grade.value] = by_e2.get(r.grade.value, 0) + 1
            by_e3[r.issue.value] = by_e3.get(r.issue.value, 0) + 1
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
            recs.append("Log Pipeline Quality Engine is healthy")
        return LogPipelineQualityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_dimension=by_e1,
            by_grade=by_e2,
            by_issue=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("log_pipeline_quality_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.dimension.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "dimension_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
