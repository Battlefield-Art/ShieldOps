"""LatencyProfilerEngine — Profile and analyze service latency patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LatencyBucket(StrEnum):
    P50 = "p50"
    P90 = "p90"
    P95 = "p95"
    P99 = "p99"
    MAX = "max"


class ServiceTier(StrEnum):
    CRITICAL = "critical"
    STANDARD = "standard"
    BACKGROUND = "background"
    BATCH = "batch"
    INTERNAL = "internal"


class BottleneckSource(StrEnum):
    DATABASE = "database"
    EXTERNAL_API = "external_api"
    CACHE_MISS = "cache_miss"
    CPU = "cpu"
    NETWORK = "network"


# --- Models ---


class LatencyProfilerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    latency_bucket: LatencyBucket = LatencyBucket.P50
    service_tier: ServiceTier = ServiceTier.STANDARD
    bottleneck_source: BottleneckSource = BottleneckSource.DATABASE
    score: float = 0.0
    latency_ms: float = 0.0
    request_count: int = 0
    error_rate: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class LatencyProfilerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    latency_bucket: LatencyBucket = LatencyBucket.P50
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LatencyProfilerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_latency_bucket: dict[str, int] = Field(default_factory=dict)
    by_service_tier: dict[str, int] = Field(default_factory=dict)
    by_bottleneck_source: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class LatencyProfilerEngine:
    """Profile and analyze service latency patterns."""

    def __init__(
        self,
        max_records: int = 200000,
        latency_threshold: float = 200.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = latency_threshold
        self._records: list[LatencyProfilerRecord] = []
        self._analyses: list[LatencyProfilerAnalysis] = []
        logger.info(
            "latency_profiler_engine.initialized",
            max_records=max_records,
            latency_threshold=latency_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        latency_bucket: LatencyBucket = LatencyBucket.P50,
        service_tier: ServiceTier = ServiceTier.STANDARD,
        bottleneck_source: BottleneckSource = BottleneckSource.DATABASE,
        score: float = 0.0,
        latency_ms: float = 0.0,
        request_count: int = 0,
        error_rate: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> LatencyProfilerRecord:
        record = LatencyProfilerRecord(
            name=name,
            latency_bucket=latency_bucket,
            service_tier=service_tier,
            bottleneck_source=bottleneck_source,
            score=score,
            latency_ms=latency_ms,
            request_count=request_count,
            error_rate=error_rate,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "latency_profiler_engine.record_added",
            record_id=record.id,
            name=name,
            latency_bucket=latency_bucket.value,
            service_tier=service_tier.value,
        )
        return record

    def get_record(self, record_id: str) -> LatencyProfilerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        latency_bucket: LatencyBucket | None = None,
        service_tier: ServiceTier | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[LatencyProfilerRecord]:
        results = list(self._records)
        if latency_bucket is not None:
            results = [r for r in results if r.latency_bucket == latency_bucket]
        if service_tier is not None:
            results = [r for r in results if r.service_tier == service_tier]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        latency_bucket: LatencyBucket = LatencyBucket.P50,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> LatencyProfilerAnalysis:
        analysis = LatencyProfilerAnalysis(
            name=name,
            latency_bucket=latency_bucket,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "latency_profiler_engine.analysis_added",
            name=name,
            latency_bucket=latency_bucket.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_latency_bottlenecks(self) -> list[dict[str, Any]]:
        """Identify services with latency bottlenecks."""
        svc_latencies: dict[str, list[LatencyProfilerRecord]] = {}
        for r in self._records:
            svc_latencies.setdefault(r.service, []).append(r)
        bottlenecks: list[dict[str, Any]] = []
        for svc, records in svc_latencies.items():
            high_latency = [r for r in records if r.latency_ms > self._threshold]
            if high_latency:
                avg_latency = round(
                    sum(r.latency_ms for r in high_latency) / len(high_latency),
                    2,
                )
                source_counts: dict[str, int] = {}
                for r in high_latency:
                    src = r.bottleneck_source.value
                    source_counts[src] = source_counts.get(src, 0) + 1
                top_source = max(source_counts, key=source_counts.get)  # type: ignore[arg-type]
                bottlenecks.append(
                    {
                        "service": svc,
                        "high_latency_count": len(high_latency),
                        "avg_latency_ms": avg_latency,
                        "top_bottleneck": top_source,
                        "severity": (
                            "critical" if avg_latency > self._threshold * 2 else "warning"
                        ),
                    }
                )
        return sorted(bottlenecks, key=lambda x: x["avg_latency_ms"], reverse=True)

    def compute_latency_percentiles(self) -> list[dict[str, Any]]:
        """Compute latency percentiles per service tier."""
        tier_records: dict[str, list[LatencyProfilerRecord]] = {}
        for r in self._records:
            tier_records.setdefault(r.service_tier.value, []).append(r)
        results: list[dict[str, Any]] = []
        for tier, records in tier_records.items():
            latencies = sorted(r.latency_ms for r in records)
            total = len(latencies)
            p50 = latencies[int(total * 0.5)] if total else 0.0
            p90 = latencies[int(total * 0.9)] if total else 0.0
            p99 = latencies[min(int(total * 0.99), total - 1)] if total else 0.0
            results.append(
                {
                    "service_tier": tier,
                    "total_samples": total,
                    "p50_ms": round(p50, 2),
                    "p90_ms": round(p90, 2),
                    "p99_ms": round(p99, 2),
                    "max_ms": round(max(latencies), 2) if latencies else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["p99_ms"], reverse=True)

    def recommend_latency_optimizations(self) -> list[dict[str, Any]]:
        """Recommend latency optimizations based on bottleneck sources."""
        recommendations: list[dict[str, Any]] = []
        db_bottlenecks = [
            r
            for r in self._records
            if r.bottleneck_source == BottleneckSource.DATABASE and r.latency_ms > self._threshold
        ]
        for r in db_bottlenecks:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "bottleneck": r.bottleneck_source.value,
                    "issue": "database_bottleneck",
                    "priority": "critical",
                    "suggestion": (
                        f"Optimize database queries for {r.service} (latency: {r.latency_ms}ms)"
                    ),
                }
            )
        cache_miss = [
            r
            for r in self._records
            if r.bottleneck_source == BottleneckSource.CACHE_MISS and r.latency_ms > self._threshold
        ]
        for r in cache_miss:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "bottleneck": r.bottleneck_source.value,
                    "issue": "cache_miss",
                    "priority": "high",
                    "suggestion": (f"Add caching for {r.service} (latency: {r.latency_ms}ms)"),
                }
            )
        ext_api = [
            r
            for r in self._records
            if r.bottleneck_source == BottleneckSource.EXTERNAL_API
            and r.latency_ms > self._threshold
        ]
        for r in ext_api:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "bottleneck": r.bottleneck_source.value,
                    "issue": "external_api_latency",
                    "priority": "medium",
                    "suggestion": (f"Add circuit breaker for external API in {r.service}"),
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        tier_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.service_tier.value
            tier_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in tier_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.latency_ms > self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service_tier": r.service_tier.value,
                        "latency_ms": r.latency_ms,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["latency_ms"], reverse=True)

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.latency_ms)
        results: list[dict[str, Any]] = []
        for svc, latencies in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_latency_ms": round(sum(latencies) / len(latencies), 2),
                }
            )
        results.sort(key=lambda x: x["avg_latency_ms"], reverse=True)
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        latencies = [r.latency_ms for r in matched]
        avg = round(sum(latencies) / len(latencies), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_latency_ms": avg,
            "above_threshold": sum(1 for lat in latencies if lat > self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> LatencyProfilerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.latency_bucket.value] = by_e1.get(r.latency_bucket.value, 0) + 1
            by_e2[r.service_tier.value] = by_e2.get(r.service_tier.value, 0) + 1
            by_e3[r.bottleneck_source.value] = by_e3.get(r.bottleneck_source.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.latency_ms > self._threshold)
        latencies = [r.latency_ms for r in self._records]
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) above threshold ({self._threshold}ms)")
        if self._records and avg_latency > self._threshold:
            recs.append(f"Avg latency {avg_latency}ms above threshold ({self._threshold}ms)")
        if not recs:
            recs.append("Latency Profiler Engine is healthy")
        return LatencyProfilerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_latency,
            by_latency_bucket=by_e1,
            by_service_tier=by_e2,
            by_bottleneck_source=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("latency_profiler_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.service_tier.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold_ms": self._threshold,
            "service_tier_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
