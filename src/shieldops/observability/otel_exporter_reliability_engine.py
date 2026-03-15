"""OtelExporterReliabilityEngine — Track OTel exporter reliability and retry behavior."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExporterHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILING = "failing"
    DEAD = "dead"


class RetryOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    EXHAUSTED = "exhausted"


class BackendType(StrEnum):
    OTLP_GRPC = "otlp_grpc"
    OTLP_HTTP = "otlp_http"
    KAFKA = "kafka"
    PROMETHEUS_REMOTE_WRITE = "prometheus_remote_write"


# --- Models ---


class OtelExporterReliabilityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    exporter_health: ExporterHealth = ExporterHealth.HEALTHY
    retry_outcome: RetryOutcome = RetryOutcome.SUCCESS
    backend_type: BackendType = BackendType.OTLP_GRPC
    score: float = 0.0
    total_sent: int = 0
    total_failed: int = 0
    retry_count: int = 0
    latency_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelExporterReliabilityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    exporter_health: ExporterHealth = ExporterHealth.HEALTHY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelExporterReliabilityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_exporter_health: dict[str, int] = Field(default_factory=dict)
    by_retry_outcome: dict[str, int] = Field(default_factory=dict)
    by_backend_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelExporterReliabilityEngine:
    """Track OTel exporter reliability and retry behavior engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelExporterReliabilityRecord] = []
        self._analyses: list[OtelExporterReliabilityAnalysis] = []
        logger.info(
            "otel_exporter_reliability_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        exporter_health: ExporterHealth = ExporterHealth.HEALTHY,
        retry_outcome: RetryOutcome = RetryOutcome.SUCCESS,
        backend_type: BackendType = BackendType.OTLP_GRPC,
        score: float = 0.0,
        total_sent: int = 0,
        total_failed: int = 0,
        retry_count: int = 0,
        latency_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> OtelExporterReliabilityRecord:
        record = OtelExporterReliabilityRecord(
            name=name,
            exporter_health=exporter_health,
            retry_outcome=retry_outcome,
            backend_type=backend_type,
            score=score,
            total_sent=total_sent,
            total_failed=total_failed,
            retry_count=retry_count,
            latency_ms=latency_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_exporter_reliability_engine.record_added",
            record_id=record.id,
            name=name,
            exporter_health=exporter_health.value,
            retry_outcome=retry_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelExporterReliabilityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        exporter_health: ExporterHealth | None = None,
        backend_type: BackendType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelExporterReliabilityRecord]:
        results = list(self._records)
        if exporter_health is not None:
            results = [r for r in results if r.exporter_health == exporter_health]
        if backend_type is not None:
            results = [r for r in results if r.backend_type == backend_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        exporter_health: ExporterHealth = ExporterHealth.HEALTHY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelExporterReliabilityAnalysis:
        analysis = OtelExporterReliabilityAnalysis(
            name=name,
            exporter_health=exporter_health,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_exporter_reliability_engine.analysis_added",
            name=name,
            exporter_health=exporter_health.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_delivery_rate(self) -> list[dict[str, Any]]:
        """Compute delivery success rate per exporter/service."""
        svc_data: dict[str, list[OtelExporterReliabilityRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            total_sent = sum(r.total_sent for r in records)
            total_failed = sum(r.total_failed for r in records)
            delivery_rate = (
                round((total_sent - total_failed) / total_sent, 4) if total_sent > 0 else 0.0
            )
            avg_latency = round(sum(r.latency_ms for r in records) / len(records), 2)
            results.append(
                {
                    "service": svc,
                    "total_sent": total_sent,
                    "total_failed": total_failed,
                    "delivery_rate": delivery_rate,
                    "avg_latency_ms": avg_latency,
                    "record_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["delivery_rate"])

    def identify_failing_exporters(self) -> list[dict[str, Any]]:
        """Identify exporters that are failing or dead."""
        failing: list[dict[str, Any]] = []
        svc_data: dict[str, list[OtelExporterReliabilityRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        for svc, records in svc_data.items():
            fail_count = sum(
                1
                for r in records
                if r.exporter_health in (ExporterHealth.FAILING, ExporterHealth.DEAD)
            )
            if fail_count > 0:
                exhausted_retries = sum(
                    1 for r in records if r.retry_outcome == RetryOutcome.EXHAUSTED
                )
                total_retries = sum(r.retry_count for r in records)
                failing.append(
                    {
                        "service": svc,
                        "failing_count": fail_count,
                        "total_records": len(records),
                        "failure_ratio": round(fail_count / len(records), 2),
                        "exhausted_retries": exhausted_retries,
                        "total_retries": total_retries,
                        "severity": "critical" if fail_count > len(records) // 2 else "warning",
                    }
                )
        return sorted(failing, key=lambda x: x["failure_ratio"], reverse=True)

    def recommend_retry_tuning(self) -> list[dict[str, Any]]:
        """Recommend retry configuration tuning."""
        recommendations: list[dict[str, Any]] = []
        for r in self._records:
            if r.retry_outcome == RetryOutcome.EXHAUSTED:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "backend_type": r.backend_type.value,
                        "issue": "retries_exhausted",
                        "priority": "high",
                        "suggestion": (
                            f"Increase max retries or backoff for {r.backend_type.value}"
                        ),
                    }
                )
            elif r.exporter_health == ExporterHealth.DEGRADED and r.retry_count > 3:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "backend_type": r.backend_type.value,
                        "issue": "excessive_retries",
                        "priority": "medium",
                        "suggestion": (
                            f"Tune retry backoff to reduce retry storms ({r.retry_count} retries)"
                        ),
                    }
                )
            elif r.exporter_health == ExporterHealth.DEAD:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "backend_type": r.backend_type.value,
                        "issue": "exporter_dead",
                        "priority": "critical",
                        "suggestion": f"Investigate dead exporter for {r.service}",
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "critical" else 1 if x["priority"] == "high" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.exporter_health.value
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
                        "exporter_health": r.exporter_health.value,
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

    def generate_report(self) -> OtelExporterReliabilityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.exporter_health.value] = by_e1.get(r.exporter_health.value, 0) + 1
            by_e2[r.retry_outcome.value] = by_e2.get(r.retry_outcome.value, 0) + 1
            by_e3[r.backend_type.value] = by_e3.get(r.backend_type.value, 0) + 1
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
            recs.append("OTel Exporter Reliability Engine is healthy")
        return OtelExporterReliabilityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_exporter_health=by_e1,
            by_retry_outcome=by_e2,
            by_backend_type=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_exporter_reliability_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.exporter_health.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "exporter_health_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
