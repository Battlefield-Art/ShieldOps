"""Agent Performance Benchmark Engine — multi-dimensional agent benchmarking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BenchmarkDimension(StrEnum):
    ACCURACY = "accuracy"
    LATENCY = "latency"
    COST_EFFICIENCY = "cost_efficiency"
    RELIABILITY = "reliability"


class BenchmarkBaseline(StrEnum):
    INDUSTRY_STANDARD = "industry_standard"
    HISTORICAL_BEST = "historical_best"
    PEER_COMPARISON = "peer_comparison"
    TARGET_SLA = "target_sla"


class PerformanceTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"


# --- Models ---


class BenchmarkRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    dimension: BenchmarkDimension = BenchmarkDimension.ACCURACY
    baseline: BenchmarkBaseline = BenchmarkBaseline.INDUSTRY_STANDARD
    trend: PerformanceTrend = PerformanceTrend.STABLE
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class BenchmarkAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    dimension: BenchmarkDimension = BenchmarkDimension.ACCURACY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BenchmarkReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    low_score_count: int = 0
    avg_score: float = 0.0
    by_dimension: dict[str, int] = Field(default_factory=dict)
    by_baseline: dict[str, int] = Field(default_factory=dict)
    by_trend: dict[str, int] = Field(default_factory=dict)
    top_low_performers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentPerformanceBenchmarkEngine:
    """Benchmark agent performance across accuracy, latency, cost, reliability."""

    def __init__(
        self,
        max_records: int = 200000,
        score_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._score_threshold = score_threshold
        self._records: list[BenchmarkRecord] = []
        self._analyses: list[BenchmarkAnalysis] = []
        logger.info(
            "agent_performance_benchmark_engine.initialized",
            max_records=max_records,
            score_threshold=score_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        agent_id: str,
        dimension: BenchmarkDimension = BenchmarkDimension.ACCURACY,
        baseline: BenchmarkBaseline = BenchmarkBaseline.INDUSTRY_STANDARD,
        trend: PerformanceTrend = PerformanceTrend.STABLE,
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> BenchmarkRecord:
        record = BenchmarkRecord(
            agent_id=agent_id,
            dimension=dimension,
            baseline=baseline,
            trend=trend,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_performance_benchmark_engine.record_added",
            record_id=record.id,
            agent_id=agent_id,
            dimension=dimension.value,
            score=score,
        )
        return record

    def get_record(self, record_id: str) -> BenchmarkRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        dimension: BenchmarkDimension | None = None,
        baseline: BenchmarkBaseline | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[BenchmarkRecord]:
        results = list(self._records)
        if dimension is not None:
            results = [r for r in results if r.dimension == dimension]
        if baseline is not None:
            results = [r for r in results if r.baseline == baseline]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        agent_id: str,
        dimension: BenchmarkDimension = BenchmarkDimension.ACCURACY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> BenchmarkAnalysis:
        analysis = BenchmarkAnalysis(
            agent_id=agent_id,
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
            "agent_performance_benchmark_engine.analysis_added",
            agent_id=agent_id,
            dimension=dimension.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_benchmark_score(self, agent_id: str) -> dict[str, Any]:
        """Multi-dimensional benchmark score for an agent."""
        agent_records = [r for r in self._records if r.agent_id == agent_id]
        if not agent_records:
            return {"agent_id": agent_id, "overall_score": 0.0, "dimensions": {}}
        dim_scores: dict[str, list[float]] = {}
        for r in agent_records:
            dim_scores.setdefault(r.dimension.value, []).append(r.score)
        dimensions: dict[str, Any] = {}
        all_avgs: list[float] = []
        for dim, scores in dim_scores.items():
            avg = round(sum(scores) / len(scores), 2)
            dimensions[dim] = {"avg_score": avg, "count": len(scores)}
            all_avgs.append(avg)
        overall = round(sum(all_avgs) / len(all_avgs), 2) if all_avgs else 0.0
        return {
            "agent_id": agent_id,
            "overall_score": overall,
            "dimensions": dimensions,
        }

    def compare_against_baseline(
        self, agent_id: str, baseline: BenchmarkBaseline
    ) -> dict[str, Any]:
        """Compare agent performance vs a specific baseline."""
        agent_records = [
            r for r in self._records if r.agent_id == agent_id and r.baseline == baseline
        ]
        if not agent_records:
            return {
                "agent_id": agent_id,
                "baseline": baseline.value,
                "comparison": "no_data",
                "delta": 0.0,
            }
        scores = [r.score for r in agent_records]
        avg_score = round(sum(scores) / len(scores), 2)
        delta = round(avg_score - self._score_threshold, 2)
        if delta > 5.0:
            comparison = "above_baseline"
        elif delta < -5.0:
            comparison = "below_baseline"
        else:
            comparison = "at_baseline"
        return {
            "agent_id": agent_id,
            "baseline": baseline.value,
            "avg_score": avg_score,
            "threshold": self._score_threshold,
            "delta": delta,
            "comparison": comparison,
        }

    def identify_performance_regressions(self) -> list[dict[str, Any]]:
        """Detect agents whose performance has degraded."""
        agent_ids = {r.agent_id for r in self._records}
        regressions: list[dict[str, Any]] = []
        for aid in agent_ids:
            agent_records = [r for r in self._records if r.agent_id == aid]
            if len(agent_records) < 2:
                continue
            mid = len(agent_records) // 2
            first_half = agent_records[:mid]
            second_half = agent_records[mid:]
            avg_first = sum(r.score for r in first_half) / len(first_half)
            avg_second = sum(r.score for r in second_half) / len(second_half)
            delta = round(avg_second - avg_first, 2)
            if delta < -5.0:
                regressions.append(
                    {
                        "agent_id": aid,
                        "avg_early": round(avg_first, 2),
                        "avg_recent": round(avg_second, 2),
                        "delta": delta,
                    }
                )
        return sorted(regressions, key=lambda x: x["delta"])

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> BenchmarkReport:
        by_dimension: dict[str, int] = {}
        by_baseline: dict[str, int] = {}
        by_trend: dict[str, int] = {}
        for r in self._records:
            by_dimension[r.dimension.value] = by_dimension.get(r.dimension.value, 0) + 1
            by_baseline[r.baseline.value] = by_baseline.get(r.baseline.value, 0) + 1
            by_trend[r.trend.value] = by_trend.get(r.trend.value, 0) + 1
        low_score_count = sum(1 for r in self._records if r.score < self._score_threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        low_agents = [
            r.agent_id
            for r in sorted(self._records, key=lambda x: x.score)
            if r.score < self._score_threshold
        ]
        top_low_performers = list(dict.fromkeys(low_agents))[:5]
        recs: list[str] = []
        if self._records and low_score_count > 0:
            recs.append(
                f"{low_score_count} benchmark(s) below score threshold ({self._score_threshold})"
            )
        if self._records and avg_score < self._score_threshold:
            recs.append(
                f"Avg benchmark score {avg_score} below threshold ({self._score_threshold})"
            )
        if not recs:
            recs.append("Agent benchmark performance is healthy")
        return BenchmarkReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            low_score_count=low_score_count,
            avg_score=avg_score,
            by_dimension=by_dimension,
            by_baseline=by_baseline,
            by_trend=by_trend,
            top_low_performers=top_low_performers,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_performance_benchmark_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        dim_dist: dict[str, int] = {}
        for r in self._records:
            key = r.dimension.value
            dim_dist[key] = dim_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "score_threshold": self._score_threshold,
            "dimension_distribution": dim_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
