"""Log Query Optimizer — optimize queries, measure latency, recommend indexes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class QueryType(StrEnum):
    FULL_TEXT = "full_text"
    AGGREGATION = "aggregation"
    FILTER = "filter"
    REGEX = "regex"
    STRUCTURED = "structured"


class OptimizationMethod(StrEnum):
    INDEX_HINT = "index_hint"
    QUERY_REWRITE = "query_rewrite"
    PARTITION_PRUNE = "partition_prune"
    CACHE_HIT = "cache_hit"
    PARALLEL_SCAN = "parallel_scan"


class PerformanceTier(StrEnum):
    FAST = "fast"
    ACCEPTABLE = "acceptable"
    SLOW = "slow"
    CRITICAL = "critical"
    TIMEOUT = "timeout"


# --- Models ---


class QueryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_name: str = ""
    query_type: QueryType = QueryType.FULL_TEXT
    optimization_method: OptimizationMethod = OptimizationMethod.INDEX_HINT
    performance_tier: PerformanceTier = PerformanceTier.ACCEPTABLE
    latency_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class QueryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_name: str = ""
    query_type: QueryType = QueryType.FULL_TEXT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class QueryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    slow_count: int = 0
    avg_latency_ms: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_tier: dict[str, int] = Field(default_factory=dict)
    top_slow: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class LogQueryOptimizer:
    """Optimize log queries, measure latency, and recommend indexes."""

    def __init__(
        self,
        max_records: int = 200000,
        latency_threshold_ms: float = 500.0,
    ) -> None:
        self._max_records = max_records
        self._latency_threshold_ms = latency_threshold_ms
        self._records: list[QueryRecord] = []
        self._analyses: list[QueryAnalysis] = []
        logger.info(
            "log_query_optimizer.initialized",
            max_records=max_records,
            latency_threshold_ms=latency_threshold_ms,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        query_name: str,
        query_type: QueryType = QueryType.FULL_TEXT,
        optimization_method: OptimizationMethod = (OptimizationMethod.INDEX_HINT),
        performance_tier: PerformanceTier = (PerformanceTier.ACCEPTABLE),
        latency_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> QueryRecord:
        record = QueryRecord(
            query_name=query_name,
            query_type=query_type,
            optimization_method=optimization_method,
            performance_tier=performance_tier,
            latency_ms=latency_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "log_query_optimizer.record_added",
            record_id=record.id,
            query_name=query_name,
            query_type=query_type.value,
        )
        return record

    def get_record(self, record_id: str) -> QueryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        query_type: QueryType | None = None,
        performance_tier: PerformanceTier | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[QueryRecord]:
        results = list(self._records)
        if query_type is not None:
            results = [r for r in results if r.query_type == query_type]
        if performance_tier is not None:
            results = [r for r in results if r.performance_tier == performance_tier]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        query_name: str,
        query_type: QueryType = QueryType.FULL_TEXT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> QueryAnalysis:
        analysis = QueryAnalysis(
            query_name=query_name,
            query_type=query_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "log_query_optimizer.analysis_added",
            query_name=query_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def optimize_query(self) -> dict[str, Any]:
        """Group by query_type; return count and avg latency_ms."""
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.query_type.value
            type_data.setdefault(key, []).append(r.latency_ms)
        result: dict[str, Any] = {}
        for qtype, latencies in type_data.items():
            result[qtype] = {
                "count": len(latencies),
                "avg_latency_ms": round(sum(latencies) / len(latencies), 2),
            }
        return result

    def measure_latency(
        self,
    ) -> list[dict[str, Any]]:
        """Return queries above latency threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.latency_ms >= self._latency_threshold_ms:
                results.append(
                    {
                        "record_id": r.id,
                        "query_name": r.query_name,
                        "query_type": (r.query_type.value),
                        "latency_ms": r.latency_ms,
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["latency_ms"],
            reverse=True,
        )

    def recommend_index(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service, avg latency, sort descending."""
        svc_data: dict[str, list[float]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r.latency_ms)
        results: list[dict[str, Any]] = []
        for svc, latencies in svc_data.items():
            results.append(
                {
                    "service": svc,
                    "avg_latency_ms": round(
                        sum(latencies) / len(latencies),
                        2,
                    ),
                    "query_count": len(latencies),
                }
            )
        results.sort(
            key=lambda x: x["avg_latency_ms"],
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> QueryReport:
        by_type: dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_tier: dict[str, int] = {}
        for r in self._records:
            by_type[r.query_type.value] = by_type.get(r.query_type.value, 0) + 1
            by_method[r.optimization_method.value] = (
                by_method.get(r.optimization_method.value, 0) + 1
            )
            by_tier[r.performance_tier.value] = by_tier.get(r.performance_tier.value, 0) + 1
        slow_count = sum(1 for r in self._records if r.latency_ms >= self._latency_threshold_ms)
        latencies = [r.latency_ms for r in self._records]
        avg = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        top = [
            r.query_name
            for r in sorted(
                self._records,
                key=lambda x: x.latency_ms,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if slow_count > 0:
            recs.append(
                f"{slow_count} query/queries above"
                f" latency threshold"
                f" ({self._latency_threshold_ms}ms)"
            )
        if not recs:
            recs.append("Log query performance is healthy")
        return QueryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            slow_count=slow_count,
            avg_latency_ms=avg,
            by_type=by_type,
            by_method=by_method,
            by_tier=by_tier,
            top_slow=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("log_query_optimizer.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.query_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "latency_threshold_ms": (self._latency_threshold_ms),
            "type_distribution": type_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
