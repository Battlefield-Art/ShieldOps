"""OtelLogCorrelationEngine — Correlate logs with traces via trace_id and span_id."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CorrelationStatus(StrEnum):
    CORRELATED = "correlated"
    ORPHANED = "orphaned"
    MISSING_CONTEXT = "missing_context"


class LogLevel(StrEnum):
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    FATAL = "fatal"


class CorrelationQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


# --- Models ---


class OtelLogCorrelationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_status: CorrelationStatus = CorrelationStatus.CORRELATED
    log_level: LogLevel = LogLevel.INFO
    correlation_quality: CorrelationQuality = CorrelationQuality.GOOD
    score: float = 0.0
    log_count: int = 0
    trace_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelLogCorrelationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_status: CorrelationStatus = CorrelationStatus.CORRELATED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelLogCorrelationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_correlation_status: dict[str, int] = Field(default_factory=dict)
    by_log_level: dict[str, int] = Field(default_factory=dict)
    by_correlation_quality: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelLogCorrelationEngine:
    """Correlate logs with traces via trace_id and span_id."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelLogCorrelationRecord] = []
        self._analyses: list[OtelLogCorrelationAnalysis] = []
        logger.info(
            "otel_log_correlation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        correlation_status: CorrelationStatus = CorrelationStatus.CORRELATED,
        log_level: LogLevel = LogLevel.INFO,
        correlation_quality: CorrelationQuality = CorrelationQuality.GOOD,
        score: float = 0.0,
        log_count: int = 0,
        trace_id: str = "",
        service: str = "",
        team: str = "",
    ) -> OtelLogCorrelationRecord:
        record = OtelLogCorrelationRecord(
            name=name,
            correlation_status=correlation_status,
            log_level=log_level,
            correlation_quality=correlation_quality,
            score=score,
            log_count=log_count,
            trace_id=trace_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_log_correlation_engine.record_added",
            record_id=record.id,
            name=name,
            correlation_status=correlation_status.value,
            log_level=log_level.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelLogCorrelationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        correlation_status: CorrelationStatus | None = None,
        log_level: LogLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelLogCorrelationRecord]:
        results = list(self._records)
        if correlation_status is not None:
            results = [r for r in results if r.correlation_status == correlation_status]
        if log_level is not None:
            results = [r for r in results if r.log_level == log_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        correlation_status: CorrelationStatus = CorrelationStatus.CORRELATED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelLogCorrelationAnalysis:
        analysis = OtelLogCorrelationAnalysis(
            name=name,
            correlation_status=correlation_status,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_log_correlation_engine.analysis_added",
            name=name,
            correlation_status=correlation_status.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_correlation_rate(self) -> list[dict[str, Any]]:
        """Compute log-to-trace correlation rate per service."""
        svc_data: dict[str, list[OtelLogCorrelationRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            correlated = sum(
                1 for r in records if r.correlation_status == CorrelationStatus.CORRELATED
            )
            total = len(records)
            rate = round(correlated / total * 100, 1) if total else 0.0
            results.append(
                {
                    "service": svc,
                    "total_logs": total,
                    "correlated": correlated,
                    "correlation_rate": rate,
                    "avg_score": round(sum(r.score for r in records) / total, 2),
                }
            )
        return sorted(results, key=lambda x: x["correlation_rate"])

    def identify_orphaned_logs(self) -> list[dict[str, Any]]:
        """Identify logs without trace context."""
        orphaned: list[dict[str, Any]] = []
        for r in self._records:
            if r.correlation_status != CorrelationStatus.CORRELATED:
                orphaned.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "log_level": r.log_level.value,
                        "correlation_status": r.correlation_status.value,
                        "log_count": r.log_count,
                    }
                )
        return sorted(orphaned, key=lambda x: x["log_count"], reverse=True)

    def recommend_instrumentation_fixes(self) -> list[dict[str, Any]]:
        """Recommend instrumentation fixes to improve log-trace correlation."""
        recommendations: list[dict[str, Any]] = []
        svc_data: dict[str, list[OtelLogCorrelationRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        for svc, records in svc_data.items():
            orphaned = sum(
                1 for r in records if r.correlation_status != CorrelationStatus.CORRELATED
            )
            total = len(records)
            if orphaned > 0:
                pct = round(orphaned / total * 100, 1) if total else 0.0
                priority = "high" if pct > 50 else ("medium" if pct > 20 else "low")
                recommendations.append(
                    {
                        "service": svc,
                        "orphaned_count": orphaned,
                        "orphaned_pct": pct,
                        "priority": priority,
                        "suggestion": (
                            f"Add trace context propagation to {svc} — "
                            f"{orphaned}/{total} logs ({pct}%) lack correlation"
                        ),
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else (1 if x["priority"] == "medium" else 2),
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.correlation_status.value
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
                        "correlation_status": r.correlation_status.value,
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

    def generate_report(self) -> OtelLogCorrelationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.correlation_status.value] = by_e1.get(r.correlation_status.value, 0) + 1
            by_e2[r.log_level.value] = by_e2.get(r.log_level.value, 0) + 1
            by_e3[r.correlation_quality.value] = by_e3.get(r.correlation_quality.value, 0) + 1
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
            recs.append("OTel Log Correlation Engine is healthy")
        return OtelLogCorrelationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_correlation_status=by_e1,
            by_log_level=by_e2,
            by_correlation_quality=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_log_correlation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.correlation_status.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "correlation_status_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
