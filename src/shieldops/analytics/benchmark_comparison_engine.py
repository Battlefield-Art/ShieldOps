"""BenchmarkComparisonEngine -- compare to benchmarks."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BenchmarkSource(StrEnum):
    CIS = "cis"
    NIST = "nist"
    INDUSTRY = "industry"
    PEER_GROUP = "peer_group"
    INTERNAL = "internal"


class IndustryVertical(StrEnum):
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    GOVERNMENT = "government"
    RETAIL = "retail"


class PerformanceQuartile(StrEnum):
    TOP = "top"
    UPPER = "upper"
    LOWER = "lower"
    BOTTOM = "bottom"


# --- Models ---


class BenchmarkComparisonRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    source: BenchmarkSource = BenchmarkSource.CIS
    vertical: IndustryVertical = IndustryVertical.TECHNOLOGY
    quartile: PerformanceQuartile = PerformanceQuartile.LOWER
    score: float = 0.0
    benchmark_value: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class BenchmarkComparisonAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    source: BenchmarkSource = BenchmarkSource.CIS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BenchmarkComparisonReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_vertical: dict[str, int] = Field(default_factory=dict)
    by_quartile: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class BenchmarkComparisonEngine:
    """Compare security posture to benchmarks."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[BenchmarkComparisonRecord] = []
        self._analyses: list[BenchmarkComparisonAnalysis] = []
        logger.info(
            "benchmark_comparison_engine.init",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        source: BenchmarkSource = BenchmarkSource.CIS,
        vertical: IndustryVertical = IndustryVertical.TECHNOLOGY,
        quartile: PerformanceQuartile = PerformanceQuartile.LOWER,
        score: float = 0.0,
        benchmark_value: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> BenchmarkComparisonRecord:
        record = BenchmarkComparisonRecord(
            name=name,
            source=source,
            vertical=vertical,
            quartile=quartile,
            score=score,
            benchmark_value=benchmark_value,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "benchmark_comparison.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> BenchmarkComparisonRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        source: BenchmarkSource | None = None,
        vertical: IndustryVertical | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[BenchmarkComparisonRecord]:
        results = list(self._records)
        if source is not None:
            results = [r for r in results if r.source == source]
        if vertical is not None:
            results = [r for r in results if r.vertical == vertical]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        source: BenchmarkSource = BenchmarkSource.CIS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> BenchmarkComparisonAnalysis:
        analysis = BenchmarkComparisonAnalysis(
            name=name,
            source=source,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def compare_to_benchmark(
        self,
    ) -> list[dict[str, Any]]:
        """Compare scores to benchmark values."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            delta = r.score - r.benchmark_value
            results.append(
                {
                    "name": r.name,
                    "score": r.score,
                    "benchmark": r.benchmark_value,
                    "delta": round(delta, 2),
                    "above": delta >= 0,
                    "source": r.source.value,
                }
            )
        return sorted(results, key=lambda x: x["delta"])

    def identify_percentile(
        self,
    ) -> dict[str, Any]:
        """Identify percentile distribution."""
        quartile_data: dict[str, int] = {}
        for r in self._records:
            key = r.quartile.value
            quartile_data[key] = quartile_data.get(key, 0) + 1
        total = len(self._records) or 1
        return {
            k: {
                "count": v,
                "pct": round(v / total * 100, 1),
            }
            for k, v in quartile_data.items()
        }

    def track_relative_performance(
        self,
    ) -> list[dict[str, Any]]:
        """Track performance relative to peers."""
        src_data: dict[
            str,
            list[BenchmarkComparisonRecord],
        ] = {}
        for r in self._records:
            src_data.setdefault(r.source.value, []).append(r)
        results: list[dict[str, Any]] = []
        for src, records in src_data.items():
            scores = [r.score for r in records]
            benchmarks = [r.benchmark_value for r in records]
            avg_score = round(sum(scores) / len(scores), 2)
            avg_bench = round(sum(benchmarks) / len(benchmarks), 2)
            results.append(
                {
                    "source": src,
                    "avg_score": avg_score,
                    "avg_benchmark": avg_bench,
                    "gap": round(avg_score - avg_bench, 2),
                    "count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["gap"])

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "source": r.source.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> BenchmarkComparisonReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.source.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.vertical.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.quartile.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Benchmark Comparison Engine healthy")
        return BenchmarkComparisonReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_source=by_e1,
            by_vertical=by_e2,
            by_quartile=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("benchmark_comparison_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.source.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "source_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
