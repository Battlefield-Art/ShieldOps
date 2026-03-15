"""TraceLogCorrelationQualityEngine — Measure trace-to-log correlation quality."""

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
    TRACE_ID_INJECTION = "trace_id_injection"
    W3C_TRACEPARENT = "w3c_traceparent"
    B3_PROPAGATION = "b3_propagation"


class CorrelationGap(StrEnum):
    NO_TRACE_ID = "no_trace_id"
    NO_SPAN_ID = "no_span_id"
    MISMATCHED_SERVICE = "mismatched_service"


class InstrumentationStatus(StrEnum):
    AUTO = "auto"
    MANUAL = "manual"
    MISSING = "missing"


# --- Models ---


class TraceLogCorrelationQualityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    method: CorrelationMethod = CorrelationMethod.TRACE_ID_INJECTION
    gap: CorrelationGap = CorrelationGap.NO_TRACE_ID
    status: InstrumentationStatus = InstrumentationStatus.AUTO
    score: float = 0.0
    correlation_pct: float = 0.0
    log_volume: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TraceLogCorrelationQualityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    method: CorrelationMethod = CorrelationMethod.TRACE_ID_INJECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TraceLogCorrelationQualityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_gap: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class TraceLogCorrelationQualityEngine:
    """Measure quality of trace-to-log correlation."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[TraceLogCorrelationQualityRecord] = []
        self._analyses: list[TraceLogCorrelationQualityAnalysis] = []
        logger.info(
            "trace_log_correlation_quality_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        method: CorrelationMethod = CorrelationMethod.TRACE_ID_INJECTION,
        gap: CorrelationGap = CorrelationGap.NO_TRACE_ID,
        status: InstrumentationStatus = InstrumentationStatus.AUTO,
        score: float = 0.0,
        correlation_pct: float = 0.0,
        log_volume: int = 0,
        service: str = "",
        team: str = "",
    ) -> TraceLogCorrelationQualityRecord:
        record = TraceLogCorrelationQualityRecord(
            name=name,
            method=method,
            gap=gap,
            status=status,
            score=score,
            correlation_pct=correlation_pct,
            log_volume=log_volume,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "trace_log_correlation_quality_engine.record_added",
            record_id=record.id,
            name=name,
            method=method.value,
            gap=gap.value,
        )
        return record

    def get_record(self, record_id: str) -> TraceLogCorrelationQualityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        method: CorrelationMethod | None = None,
        status: InstrumentationStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TraceLogCorrelationQualityRecord]:
        results = list(self._records)
        if method is not None:
            results = [r for r in results if r.method == method]
        if status is not None:
            results = [r for r in results if r.status == status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        method: CorrelationMethod = CorrelationMethod.TRACE_ID_INJECTION,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TraceLogCorrelationQualityAnalysis:
        analysis = TraceLogCorrelationQualityAnalysis(
            name=name,
            method=method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "trace_log_correlation_quality_engine.analysis_added",
            name=name,
            method=method.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def measure_correlation_coverage(self) -> list[dict[str, Any]]:
        """Measure what % of logs have trace context per service."""
        svc_data: dict[str, list[float]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r.correlation_pct)
        results: list[dict[str, Any]] = []
        for svc, pcts in svc_data.items():
            avg_pct = round(sum(pcts) / len(pcts), 2)
            results.append(
                {
                    "service": svc,
                    "avg_correlation_pct": avg_pct,
                    "sample_count": len(pcts),
                    "coverage_grade": "excellent"
                    if avg_pct >= 90
                    else "good"
                    if avg_pct >= 70
                    else "fair"
                    if avg_pct >= 50
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["avg_correlation_pct"], reverse=True)

    def identify_correlation_gaps(self) -> list[dict[str, Any]]:
        """Identify services with correlation gaps."""
        gaps: list[dict[str, Any]] = []
        svc_gaps: dict[str, dict[str, int]] = {}
        for r in self._records:
            if r.status == InstrumentationStatus.MISSING or r.correlation_pct < 50:
                svc_gaps.setdefault(r.service, {})
                gap_type = r.gap.value
                svc_gaps[r.service][gap_type] = svc_gaps[r.service].get(gap_type, 0) + 1
        for svc, gap_types in svc_gaps.items():
            total_issues = sum(gap_types.values())
            gaps.append(
                {
                    "service": svc,
                    "total_issues": total_issues,
                    "gap_types": gap_types,
                    "priority": "high"
                    if total_issues > 5
                    else "medium"
                    if total_issues > 2
                    else "low",
                }
            )
        return sorted(gaps, key=lambda x: x["total_issues"], reverse=True)

    def recommend_instrumentation_changes(self) -> list[dict[str, Any]]:
        """Recommend instrumentation changes to improve correlation."""
        recommendations: list[dict[str, Any]] = []
        missing = [r for r in self._records if r.status == InstrumentationStatus.MISSING]
        svc_missing: dict[str, int] = {}
        for r in missing:
            svc_missing[r.service] = svc_missing.get(r.service, 0) + 1
        for svc, count in svc_missing.items():
            recommendations.append(
                {
                    "service": svc,
                    "issue": "missing_instrumentation",
                    "count": count,
                    "priority": "high",
                    "suggestion": f"Add auto-instrumentation for {svc} ({count} gaps)",
                }
            )
        manual = [r for r in self._records if r.status == InstrumentationStatus.MANUAL]
        svc_manual: dict[str, list[float]] = {}
        for r in manual:
            svc_manual.setdefault(r.service, []).append(r.correlation_pct)
        for svc, pcts in svc_manual.items():
            avg = round(sum(pcts) / len(pcts), 2)
            if avg < 70:
                recommendations.append(
                    {
                        "service": svc,
                        "issue": "low_manual_correlation",
                        "avg_correlation_pct": avg,
                        "priority": "medium",
                        "suggestion": f"Upgrade {svc} to auto-instrumentation (current: {avg}%)",
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
            key = r.method.value
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
                        "method": r.method.value,
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

    def generate_report(self) -> TraceLogCorrelationQualityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.method.value] = by_e1.get(r.method.value, 0) + 1
            by_e2[r.gap.value] = by_e2.get(r.gap.value, 0) + 1
            by_e3[r.status.value] = by_e3.get(r.status.value, 0) + 1
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
            recs.append("Trace Log Correlation Quality Engine is healthy")
        return TraceLogCorrelationQualityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_method=by_e1,
            by_gap=by_e2,
            by_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("trace_log_correlation_quality_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.method.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "method_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
